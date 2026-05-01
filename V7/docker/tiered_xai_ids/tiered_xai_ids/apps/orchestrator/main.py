import asyncio
import logging
import random
import time
from collections import deque
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

import httpx
from fastapi import Depends, FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

from tiered_xai_ids.shared.auth import require_internal_key
from tiered_xai_ids.shared.attack_utils import infer_attack_type
from tiered_xai_ids.shared.config import OrchestratorSettings, get_orchestrator_settings
from tiered_xai_ids.shared.correlation import CorrelationIdMiddleware, get_correlation_id
from tiered_xai_ids.shared.email_notifier import EmailNotifier
from tiered_xai_ids.shared.fuzzy_trust import TrustRegistry
from tiered_xai_ids.shared.http_client import get_json, post_json
from tiered_xai_ids.shared.logging_config import configure_logging
from tiered_xai_ids.shared.schemas import (
    AttackCommandRequest,
    Classification,
    DetectionBranchConfig,
    DependencyHealth,
    ForwardStatus,
    HealthResponse,
    LegacyV2XTelemetry,
    OrchestratorIngestResponse,
    RawLogInput,
    SensorEvent,
    SensorIngestResponse,
)


logger = logging.getLogger(__name__)
location_history: dict[str, list[float]] = {}
TRAINING_QUARANTINE_RECOVERY_SECONDS = 20.0
DDOS_SAFE_MAX_ACTUAL_PACKETS = 8
DDOS_SAFE_INTERVAL_SECONDS = 0.75


def create_app() -> FastAPI:
    settings = get_orchestrator_settings()
    configure_logging(service_name=settings.service_name, level=settings.log_level)
    app = FastAPI(title="Tiered IDS Orchestrator", version="1.0.0")
    app.add_middleware(CorrelationIdMiddleware)
    origins = [origin.strip() for origin in settings.allowed_origins.split(",") if origin.strip()]
    if not origins:
        origins = ["*"]
    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    recent_requests: deque[dict[str, str | bool]] = deque(maxlen=200)
    attack_logs: deque[dict[str, str]] = deque(maxlen=250)
    attack_lock = asyncio.Lock()
    attack_task: asyncio.Task[None] | None = None
    alert_tasks: set[asyncio.Task[None]] = set()
    inflight_packets: set[asyncio.Task[Any]] = set()
    live_subscribers: set[asyncio.Queue[dict[str, Any]]] = set()
    trust_registry = TrustRegistry()
    detection_branches = DetectionBranchConfig(
        ddos_enabled=settings.ddos_enabled,
        gps_enabled=settings.gps_spoof_enabled,
    )
    # Per-specialist fanout flags — when False the orchestrator stops sending
    # traffic to that node, which realistically disables it from the FL process.
    specialist_nodes_enabled: dict[str, bool] = {"a": True, "b": True}
    # Cache for the federated attack weights shown on the 8200 panel.
    _cached_specialist_scores: dict[str, float] = {}
    _specialist_score_last_fetch: dict[str, float] = {}
    federated_training_quarantine: dict[str, dict[str, Any]] = {
        "ids-node-a": {
            "quarantined": False,
            "last_suspicious_at": 0.0,
            "updated_at": "",
            "reason": "",
        },
        "ids-node-b": {
            "quarantined": False,
            "last_suspicious_at": 0.0,
            "updated_at": "",
            "reason": "",
        },
    }
    email_notifier = EmailNotifier(
        admin_email=settings.admin_email,
        smtp_host=settings.smtp_host,
        smtp_port=settings.smtp_port,
        smtp_user=settings.smtp_user,
        smtp_password=settings.smtp_password.get_secret_value(),
        smtp_from=settings.smtp_from,
        smtp_use_tls=settings.smtp_use_tls,
        cooldown_seconds=settings.alert_cooldown_seconds,
    )
    attack_state: dict[str, Any] = {
        "is_attacking": False,
        "attack_type": None,
        "packet_sent": 0,
        "packets_delivered": 0,
        "packets_failed": 0,
        "start_time": None,
        "current_vehicle": None,
        "stop_requested": False,
        "last_error": None,
        "federated_training_quarantine": {
            "ids-node-a": {"quarantined": False, "updated_at": "", "reason": ""},
            "ids-node-b": {"quarantined": False, "updated_at": "", "reason": ""},
        },
    }
    # Tracks which attack types have been confirmed malicious in the current round.
    # Once set, subsequent packets of that type are short-circuited (no LLM/pipeline).
    # Cleared when the attack round ends.
    _attack_confirmed: dict[str, SensorIngestResponse] = {}

    def append_attack_log(level: str, message: str) -> None:
        item = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "level": level,
            "message": message,
        }
        attack_logs.appendleft(item)
        try:
            loop = asyncio.get_running_loop()
            loop.create_task(
                _publish_live_snapshot(
                    settings,
                    recent_requests,
                    attack_logs,
                    attack_state,
                    inflight_packets,
                    live_subscribers,
                    detection_branches,
                    trust_registry,
                )
            )
        except RuntimeError:
            # No running loop during bootstrap/tests.
            pass

    def build_stats() -> dict[str, Any]:
        uptime_seconds = 0
        if attack_state["start_time"] is not None:
            uptime_seconds = max(0, int(time.time() - float(attack_state["start_time"])))
        return {
            "is_attacking": attack_state["is_attacking"],
            "attack_type": attack_state["attack_type"],
            "total_packets_sent": attack_state["packet_sent"],
            "packets_delivered": attack_state["packets_delivered"],
            "packets_failed": attack_state["packets_failed"],
            "inflight_packets": len(inflight_packets),
            "active_for_seconds": uptime_seconds,
            "current_vehicle": attack_state["current_vehicle"],
            "last_error": attack_state["last_error"],
            "federated_training_quarantine": {
                node_id: {
                    "quarantined": bool(node_state.get("quarantined", False)),
                    "updated_at": node_state.get("updated_at", ""),
                    "reason": node_state.get("reason", ""),
                }
                for node_id, node_state in federated_training_quarantine.items()
            },
        }

    def _node_url(node_id: str) -> str:
        if node_id == "ids-node-a":
            return settings.ids_a_url.rstrip("/")
        if node_id == "ids-node-b":
            return settings.ids_b_url.rstrip("/")
        raise ValueError(f"unsupported_node_id={node_id}")

    def _sync_attack_state_quarantine() -> None:
        attack_state["federated_training_quarantine"] = {
            node_id: {
                "quarantined": bool(node_state.get("quarantined", False)),
                "updated_at": node_state.get("updated_at", ""),
                "reason": node_state.get("reason", ""),
            }
            for node_id, node_state in federated_training_quarantine.items()
        }

    async def _set_training_quarantine(node_id: str, quarantined: bool, reason: str) -> None:
        node_state = federated_training_quarantine.get(node_id)
        if node_state is None:
            return
        if bool(node_state.get("quarantined", False)) == quarantined:
            return

        node_state["quarantined"] = quarantined
        node_state["updated_at"] = time.strftime("%Y-%m-%dT%H:%M:%S")
        node_state["reason"] = reason
        _sync_attack_state_quarantine()
        action = "quarantined" if quarantined else "restored"
        append_attack_log("warning" if quarantined else "info", f"[COORD] {node_id} {action}: {reason}")

        payload = {
            "node_id": node_id,
            "quarantined": quarantined,
            "reason": reason,
            "source": settings.service_name,
        }
        targets = [
            ("global-model", f"{settings.global_model_url.rstrip('/')}/v1/federated/quarantine"),
            (node_id, f"{_node_url(node_id)}/v1/federated/quarantine"),
        ]
        for target_name, endpoint in targets:
            try:
                await post_json(endpoint, payload, timeout_seconds=min(10.0, settings.request_timeout_seconds))
                append_attack_log(
                    "info",
                    f"[COORD] command_ack target={target_name} node={node_id} quarantined={quarantined}",
                )
            except Exception as exc:
                append_attack_log(
                    "error",
                    f"[COORD] command_failed target={target_name} node={node_id} error={_safe_error_text(exc)}",
                )

    async def _evaluate_training_quarantine(
        *,
        node_id: str,
        area: int,
        sensor_response: SensorIngestResponse,
    ) -> None:
        node_state = federated_training_quarantine.get(node_id)
        if node_state is None:
            return
        label = str(sensor_response.event.classification.label).lower()
        suspicious = bool(sensor_response.suspicious) or label in {"suspicious", "malicious"}
        now = time.time()
        if suspicious:
            node_state["last_suspicious_at"] = now
            if not bool(node_state.get("quarantined", False)):
                await _set_training_quarantine(
                    node_id=node_id,
                    quarantined=True,
                    reason=f"area={area} classification={label}",
                )
            return

        if not bool(node_state.get("quarantined", False)):
            return
        last_suspicious = float(node_state.get("last_suspicious_at", now))
        stable_seconds = max(0.0, now - last_suspicious)
        if stable_seconds >= TRAINING_QUARANTINE_RECOVERY_SECONDS:
            await _set_training_quarantine(
                node_id=node_id,
                quarantined=False,
                reason=f"stable_for_{int(stable_seconds)}s",
            )

    def current_detection_config() -> DetectionBranchConfig:
        return DetectionBranchConfig(
            ddos_enabled=detection_branches.ddos_enabled,
            gps_enabled=detection_branches.gps_enabled,
        )

    def apply_detection_config(payload: RawLogInput) -> RawLogInput:
        merged = payload.model_copy(deep=True)
        merged.detection = current_detection_config()
        return merged

    def severity_rank(label: str) -> int:
        normalized = (label or "").strip().lower()
        if normalized == "malicious":
            return 2
        if normalized == "suspicious":
            return 1
        return 0

    async def notify_admin_if_needed(payload: RawLogInput, sensor_response: SensorIngestResponse) -> None:
        if not email_notifier.configured:
            return
        event = sensor_response.event
        effective_label = event.classification.label
        if effective_label == "benign" and sensor_response.suspicious:
            effective_label = "suspicious"
        threshold = (settings.alert_min_severity or "suspicious").strip().lower()
        threshold_rank = severity_rank("malicious" if threshold == "malicious" else "suspicious")
        if severity_rank(effective_label) < threshold_rank:
            return

        subject = (
            f"[Tiered IDS] {effective_label.upper()} detection "
            f"on {payload.source_device} ({payload.log_type})"
        )
        body = (
            "Tiered IDS detection alert\n\n"
            f"Timestamp: {event.timestamp.isoformat()}\n"
            f"Device: {payload.source_device}\n"
            f"Log type: {payload.log_type}\n"
            f"Classification: {event.classification.label}\n"
            f"Confidence: {event.classification.confidence:.3f}\n"
            f"Anomaly score: {event.classification.anomaly_score:.3f}\n"
            f"Priority: {event.priority}\n"
            f"Event ID: {event.event_id}\n"
            f"Correlation ID: {sensor_response.correlation_id}\n"
            f"DDoS branch enabled: {event.detection.ddos_enabled}\n"
            f"GPS branch enabled: {event.detection.gps_enabled}\n"
            f"Evidence: {', '.join(event.evidence[:8]) or 'n/a'}\n"
        )
        sent, detail = await email_notifier.send_alert(
            subject=subject,
            body=body,
            dedupe_key=f"event:{event.event_id}",
        )
        if sent:
            append_attack_log("info", f"admin_alert_sent event={event.event_id} to={email_notifier.admin_email}")
        else:
            logger.warning("admin_alert_not_sent event=%s reason=%s", event.event_id, detail)

    async def process_raw_log(payload: RawLogInput) -> OrchestratorIngestResponse:
        payload = apply_detection_config(payload)
        incoming_attack_type = infer_attack_type(str(payload.log_type), payload.raw_log)
        incoming_area = _extract_area_from_raw_log(payload.raw_log)

        if await _is_attack_suppressed(incoming_attack_type, incoming_area):
            return _build_cross_learning_suppressed_response(payload)

        # Suppress duplicate attack packets only while an active attack round is
        # running and that attack type has already been confirmed malicious.
        # Tied to attack_state["is_attacking"] so normal traffic is never affected.
        _active_attack_type = attack_state["attack_type"] if attack_state["is_attacking"] else None
        if (
            _active_attack_type
            and incoming_attack_type == _active_attack_type
            and _active_attack_type in _attack_confirmed
        ):
            _confirmed = _attack_confirmed[_active_attack_type]
            return OrchestratorIngestResponse(
                correlation_id=get_correlation_id(),
                sensor_response=SensorIngestResponse(
                    correlation_id=get_correlation_id(),
                    suspicious=True,
                    forward_status=ForwardStatus(forwarded=False, endpoint="suppressed"),
                    event=SensorEvent(
                        event_id=str(uuid4()),
                        timestamp=datetime.now(timezone.utc),
                        source_device=payload.source_device,
                        log_type=payload.log_type,
                        detection=payload.detection,
                        classification=_confirmed.event.classification,
                        evidence=_confirmed.event.evidence,
                        priority=_confirmed.event.priority,
                        raw_excerpt=payload.raw_log[:200],
                    ),
                ),
            )

        endpoint = f"{settings.sensor_node_url.rstrip('/')}/v1/ingest/log"
        try:
            _, data = await post_json(
                endpoint,
                payload.model_dump(mode="json"),
                timeout_seconds=min(15.0, settings.request_timeout_seconds),
            )
            sensor_response = SensorIngestResponse.model_validate(data)
        except Exception as exc:
            error_text = _safe_error_text(exc)
            logger.error("orchestrator_sensor_forward_failed error=%s", error_text)
            raise HTTPException(status_code=502, detail=f"Sensor node unreachable: {error_text}") from exc

        # Fan out to ENABLED specialist IDS nodes only (fire-and-forget).
        # Disabled nodes receive no traffic and therefore accumulate no training
        # samples — this is the correct way to model a node being "offline".
        # We encode the current enabled state of both specialists as query params so
        # each receiving node knows whether the other specialist is online and can
        # decide whether to update its cross-type EWA / training buffer.
        log_dump = payload.model_dump(mode="json")
        _a_flag = "1" if specialist_nodes_enabled["a"] else "0"
        _b_flag = "1" if specialist_nodes_enabled["b"] else "0"
        # Fetch the same federated attack weights shown on the 8200 panel.
        # If the primary specialist is offline, these weights decide whether
        # cross-detection is allowed and are passed to the backup specialist.
        _ddos_specialist_score: float = _cached_specialist_scores.get("ddos", 0.0)
        _gps_specialist_score: float = _cached_specialist_scores.get("gps_spoof", 0.0)
        _now_ts = time.time()
        if not specialist_nodes_enabled["a"] and _now_ts - _specialist_score_last_fetch.get("ddos", 0.0) > 3.0:
            _ddos_specialist_score = await _get_panel_attack_weight("ddos")
            _cached_specialist_scores["ddos"] = _ddos_specialist_score
            _specialist_score_last_fetch["ddos"] = _now_ts
        if not specialist_nodes_enabled["b"] and _now_ts - _specialist_score_last_fetch.get("gps_spoof", 0.0) > 3.0:
            _gps_specialist_score = await _get_panel_attack_weight("gps_spoof")
            _cached_specialist_scores["gps_spoof"] = _gps_specialist_score
            _specialist_score_last_fetch["gps_spoof"] = _now_ts
        _node_state_qs = (
            f"?specialist_a_enabled={_a_flag}&specialist_b_enabled={_b_flag}"
            f"&ddos_specialist_score={_ddos_specialist_score:.4f}"
            f"&gps_specialist_score={_gps_specialist_score:.4f}"
        )
        fanout_urls: list[str] = []
        if specialist_nodes_enabled["a"]:
            fanout_urls.append(settings.ids_a_url.rstrip("/"))
        if specialist_nodes_enabled["b"]:
            fanout_urls.append(settings.ids_b_url.rstrip("/"))
        for ids_url in fanout_urls:
            task = asyncio.create_task(
                _fanout_to_specialist(
                    endpoint=f"{ids_url}/v1/ingest/log{_node_state_qs}",
                    payload=log_dump,
                    timeout_seconds=min(30.0, settings.request_timeout_seconds),
                )
            )
            inflight_packets.add(task)
            task.add_done_callback(lambda done_task: inflight_packets.discard(done_task))

        # If this is the first confirmed malicious packet in an active attack round,
        # record it so all subsequent packets of the same type are short-circuited.
        _cur_attack = attack_state["attack_type"] if attack_state["is_attacking"] else None
        if (
            _cur_attack
            and incoming_attack_type == _cur_attack
            and _cur_attack not in _attack_confirmed
            and sensor_response.event.classification.label == "malicious"
        ):
            _attack_confirmed[_cur_attack] = sensor_response
            append_attack_log(
                "warning",
                f"attack_confirmed type={_cur_attack} — subsequent packets will be short-circuited",
            )

        # Update fuzzy trust for the sending vehicle and active IDS nodes
        trust_registry.update_vehicle(
            payload.source_device,
            confidence=sensor_response.event.classification.confidence,
            anomaly_score=sensor_response.event.classification.anomaly_score,
            is_suspicious=sensor_response.suspicious,
            delivered=True,
        )
        _is_attack_now = attack_state["is_attacking"]
        trust_registry.update_node("ids-node-a", "ids_node", under_attack=_is_attack_now and specialist_nodes_enabled["a"])
        trust_registry.update_node("ids-node-b", "ids_node", under_attack=_is_attack_now and specialist_nodes_enabled["b"])
        trust_registry.update_node("fog-server", "fog_node", under_attack=_is_attack_now)

        response = OrchestratorIngestResponse(
            correlation_id=get_correlation_id(),
            sensor_response=sensor_response,
        )
        _area = incoming_area or 1
        _area_found = incoming_area is not None

        _training_node = None
        if _area_found:
            _training_node = "ids-node-a" if _area == 1 else ("ids-node-b" if _area == 2 else None)
        if _training_node is not None:
            await _evaluate_training_quarantine(
                node_id=_training_node,
                area=_area,
                sensor_response=sensor_response,
            )

        recent_requests.appendleft(
            {
                "source_device": payload.source_device,
                "log_type": str(payload.log_type),
                "timestamp": payload.timestamp.isoformat(),
                "suspicious": sensor_response.suspicious,
                "event_id": sensor_response.event.event_id,
                "ddos_enabled": sensor_response.event.detection.ddos_enabled,
                "gps_enabled": sensor_response.event.detection.gps_enabled,
                "area": _area,
                "raw_excerpt": sensor_response.event.raw_excerpt[:120],
            }
        )
        if email_notifier.configured:
            task = asyncio.create_task(notify_admin_if_needed(payload, sensor_response))
            alert_tasks.add(task)
            task.add_done_callback(lambda done_task: alert_tasks.discard(done_task))
        await _publish_live_snapshot(
            settings,
            recent_requests,
            attack_logs,
            attack_state,
            inflight_packets,
            live_subscribers,
            detection_branches,
            trust_registry,
        )
        return response

    async def process_legacy_telemetry(telemetry: LegacyV2XTelemetry) -> OrchestratorIngestResponse:
        return await process_raw_log(_legacy_to_raw_log(telemetry))

    _FEDERATED_VISIBILITY_THRESHOLD = 0.75
    _SPECIALIST_AREA_BY_ATTACK = {"ddos": 1, "gps_spoof": 2}

    def _extract_area_from_raw_log(raw_log: str) -> int | None:
        marker = "location=Area "
        idx = raw_log.find(marker)
        if idx < 0:
            return None
        start = idx + len(marker)
        digits: list[str] = []
        for char in raw_log[start:]:
            if not char.isdigit():
                break
            digits.append(char)
        if not digits:
            return None
        try:
            return int("".join(digits))
        except ValueError:
            return None

    def _primary_node_for_attack(attack_kind: str) -> str | None:
        if attack_kind == "ddos":
            return "a"
        if attack_kind == "gps_spoof":
            return "b"
        return None

    def _backup_node_for_attack(attack_kind: str) -> str | None:
        if attack_kind == "ddos":
            return "b"
        if attack_kind == "gps_spoof":
            return "a"
        return None

    def _node_enabled(node_key: str | None) -> bool:
        if node_key == "a":
            return specialist_nodes_enabled["a"]
        if node_key == "b":
            return specialist_nodes_enabled["b"]
        return False

    async def _get_node_attack_score(node_key: str | None, attack_kind: str) -> float:
        if node_key == "a":
            url = f"{settings.ids_a_url.rstrip('/')}/v1/federated/model/state"
        elif node_key == "b":
            url = f"{settings.ids_b_url.rstrip('/')}/v1/federated/model/state"
        else:
            return 0.0
        try:
            data = await get_json(url, timeout_seconds=2.0)
            return float(data.get("node_fl_scores", {}).get(attack_kind, 0.0))
        except Exception:
            return 0.0

    async def _get_backup_cross_score(attack_kind: str) -> float:
        return await _get_node_attack_score(_backup_node_for_attack(attack_kind), attack_kind)

    async def _get_panel_attack_weight(attack_kind: str) -> float:
        """Fetch the exact DDoS/GPS weight displayed on the 8200 panel."""
        cached = _cached_specialist_scores.get(attack_kind)
        now = time.time()
        if cached is not None and now - _specialist_score_last_fetch.get(attack_kind, 0.0) <= 3.0:
            return cached
        try:
            data = await get_json(
                f"{settings.global_model_url.rstrip('/')}/v1/federated/policy",
                timeout_seconds=2.5,
            )
            weights = data.get("weights", {})
            if attack_kind == "gps_spoof":
                value = (
                    weights.get("gps_spoof")
                    if "gps_spoof" in weights
                    else weights.get("gps-spoof", weights.get("gps_spoofing", 0.0))
                )
            else:
                value = weights.get(attack_kind, 0.0)
            score = float(value or 0.0)
            _cached_specialist_scores[attack_kind] = score
            _specialist_score_last_fetch[attack_kind] = now
            return score
        except Exception:
            return float(cached or 0.0)

    def _build_cross_learning_suppressed_response(payload: RawLogInput) -> OrchestratorIngestResponse:
        return OrchestratorIngestResponse(
            correlation_id=get_correlation_id(),
            sensor_response=SensorIngestResponse(
                correlation_id=get_correlation_id(),
                suspicious=False,
                forward_status=ForwardStatus(forwarded=False, endpoint="cross_learning_gate"),
                event=SensorEvent(
                    event_id=str(uuid4()),
                    timestamp=datetime.now(timezone.utc),
                    source_device=payload.source_device,
                    log_type=payload.log_type,
                    detection=payload.detection,
                    classification=Classification(label="benign", confidence=0.0, anomaly_score=0.0),
                    evidence=[],
                    priority="low",
                    raw_excerpt="suppressed until federated attack weight exceeds 0.75",
                ),
            ),
        )

    async def _get_specialist_score(attack_kind: str) -> float:
        """Fetch the dedicated specialist's own specialty EWA score for attack_kind.

        Node A is the ddos specialist; Node B is the gps_spoof specialist.
        The container is still running even when disabled (it just receives no traffic),
        so its specialty score is still valid — this is the same number shown as
        'Node A Weight' / 'Node B Weight' on the federated policy panel."""
        if attack_kind == "ddos":
            url = f"{settings.ids_a_url.rstrip('/')}/v1/federated/model/state"
        elif attack_kind == "gps_spoof":
            url = f"{settings.ids_b_url.rstrip('/')}/v1/federated/model/state"
        else:
            return 0.0
        try:
            data = await get_json(url, timeout_seconds=2.0)
            return float(data.get("node_fl_scores", {}).get(attack_kind, 0.0))
        except Exception:
            return 0.0

    async def _is_attack_suppressed(attack_kind: str, area: int | None = None) -> bool:
        """Return True when the dedicated specialist area/node for this attack type is
        unavailable and its global attack weight is still at or below 0.75, meaning
        the surviving node hasn't accumulated enough FL knowledge to detect it.

        Uses the specialist's own specialty score (same value shown on the
        federated policy panel) so the suppression gate and the UI are always
        in agreement."""
        if attack_kind not in ("ddos", "gps_spoof"):
            return False
        panel_weight: float | None = None
        specialist_area = _SPECIALIST_AREA_BY_ATTACK.get(attack_kind)
        if area is not None and specialist_area is not None and area != specialist_area:
            panel_weight = await _get_panel_attack_weight(attack_kind)
            if panel_weight <= _FEDERATED_VISIBILITY_THRESHOLD:
                return True
        primary_node = _primary_node_for_attack(attack_kind)
        if _node_enabled(primary_node):
            return False
        if panel_weight is None:
            panel_weight = await _get_panel_attack_weight(attack_kind)
        return panel_weight <= _FEDERATED_VISIBILITY_THRESHOLD

    async def dispatch_attack_packet(telemetry: LegacyV2XTelemetry) -> None:
        # Silently drop attack packets when suppression is active. The packet
        # still leaves the attacker, but the orchestrator pretends it never saw
        # it: no pipeline entry, no fanout, no counters, no snapshot publish.
        attack_kind = attack_state.get("attack_type") or ""
        raw_payload = _legacy_to_raw_log(telemetry)
        attack_area = _extract_area_from_raw_log(raw_payload.raw_log)
        if attack_kind and await _is_attack_suppressed(attack_kind, attack_area):
            return
        try:
            await process_raw_log(raw_payload)
            attack_state["packets_delivered"] += 1
        except Exception as exc:
            attack_state["packets_failed"] += 1
            attack_state["last_error"] = _safe_error_text(exc)
        finally:
            await _publish_live_snapshot(
                settings,
                recent_requests,
                attack_logs,
                attack_state,
                inflight_packets,
                live_subscribers,
                detection_branches,
                trust_registry,
            )

    async def run_attack(
        attack_type: str,
        vehicle_id: str,
        duration_seconds: int,
        packet_count: int,
    ) -> None:
        nonlocal attack_task
        preview_payload = _legacy_to_raw_log(_build_telemetry_for_attack(attack_type=attack_type, vehicle_id=vehicle_id))
        preview_area = _extract_area_from_raw_log(preview_payload.raw_log)
        suppressed = await _is_attack_suppressed(attack_type, preview_area)
        if suppressed:
            # Silent mode: revert all state set by start_attack so the system
            # appears completely idle to the panel and the LLM. The attack
            # request still "runs" in the sense that the loop sleeps, but no
            # packets are dispatched and no logs are written.
            attack_state["is_attacking"] = False
            attack_state["attack_type"] = None
            attack_state["stop_requested"] = False
            attack_state["start_time"] = None
            attack_state["current_vehicle"] = None
            attack_task = None
            return
        requested_packet_count = packet_count
        actual_packet_count = packet_count
        if attack_type == "ddos":
            actual_packet_count = max(1, min(packet_count, DDOS_SAFE_MAX_ACTUAL_PACKETS))
        append_attack_log(
            "warning",
            (
                f"attack_started type={attack_type} vehicle={vehicle_id} "
                f"requested_packets={requested_packet_count} emitted_packets={actual_packet_count}"
            ),
        )
        started = time.time()
        sleep_seconds = DDOS_SAFE_INTERVAL_SECONDS if attack_type == "ddos" else 0.45

        try:
            for _ in range(actual_packet_count):
                if attack_state["stop_requested"] or (time.time() - started) >= duration_seconds:
                    break

                telemetry = _build_telemetry_for_attack(attack_type=attack_type, vehicle_id=vehicle_id)
                if attack_type == "ddos":
                    telemetry.message_type = (
                        f"ATTACK_DDOS_SUMMARY_VIRTUAL_{requested_packet_count}_EMITTED_{actual_packet_count}"
                    )
                attack_state["packet_sent"] += 1
                packet_task = asyncio.create_task(dispatch_attack_packet(telemetry))
                inflight_packets.add(packet_task)
                packet_task.add_done_callback(lambda done_task: inflight_packets.discard(done_task))

                await asyncio.sleep(sleep_seconds)
        finally:
            attack_state["is_attacking"] = False
            attack_state["attack_type"] = None
            attack_state["stop_requested"] = False
            attack_state["start_time"] = None
            attack_state["current_vehicle"] = None
            attack_task = None
            _attack_confirmed.clear()
            append_attack_log("info", "attack_finished")
            await _publish_live_snapshot(
                settings,
                recent_requests,
                attack_logs,
                attack_state,
                inflight_packets,
                live_subscribers,
                detection_branches,
                trust_registry,
            )

    async def start_attack(kind: str, payload: AttackCommandRequest) -> dict[str, Any]:
        nonlocal attack_task
        async with attack_lock:
            if attack_task is not None and not attack_task.done():
                raise HTTPException(status_code=409, detail="Another attack simulation is already running")

            vehicle_id = payload.vehicle_id.strip() or "V001"
            # Suppression mode: silently accept the request but never flip
            # is_attacking, never log, never publish — the system stays idle.
            preview_payload = _legacy_to_raw_log(_build_telemetry_for_attack(attack_type=kind, vehicle_id=vehicle_id))
            preview_area = _extract_area_from_raw_log(preview_payload.raw_log)
            if await _is_attack_suppressed(kind, preview_area):
                emitted_packet_count = (
                    max(1, min(payload.packet_count, DDOS_SAFE_MAX_ACTUAL_PACKETS))
                    if kind == "ddos"
                    else payload.packet_count
                )
                return {
                    "status": "attack_started",
                    "attack_type": kind,
                    "vehicle_id": vehicle_id,
                    "duration_seconds": payload.duration_seconds,
                    "packet_count": emitted_packet_count,
                    "requested_packet_count": payload.packet_count,
                    "simulation_mode": "cloud_safe_summary" if kind == "ddos" else "direct_packet_stream",
                }
            attack_state["is_attacking"] = True
            attack_state["attack_type"] = kind
            attack_state["stop_requested"] = False
            attack_state["start_time"] = time.time()
            attack_state["current_vehicle"] = vehicle_id
            attack_state["last_error"] = None

            attack_task = asyncio.create_task(
                run_attack(
                    attack_type=kind,
                    vehicle_id=vehicle_id,
                    duration_seconds=payload.duration_seconds,
                    packet_count=payload.packet_count,
                )
            )

        response = {
            "status": "attack_started",
            "attack_type": kind,
            "vehicle_id": vehicle_id,
            "duration_seconds": payload.duration_seconds,
            "packet_count": (
                max(1, min(payload.packet_count, DDOS_SAFE_MAX_ACTUAL_PACKETS))
                if kind == "ddos"
                else payload.packet_count
            ),
            "requested_packet_count": payload.packet_count,
            "simulation_mode": "cloud_safe_summary" if kind == "ddos" else "direct_packet_stream",
        }
        await _publish_live_snapshot(
            settings,
            recent_requests,
            attack_logs,
            attack_state,
            inflight_packets,
            live_subscribers,
            detection_branches,
            trust_registry,
        )
        return response

    @app.get("/health", response_model=HealthResponse)
    async def health() -> HealthResponse:
        dependencies = await _collect_dependency_health(settings)
        degraded = any(dep.status != "ok" for dep in dependencies)
        return HealthResponse(
            service=settings.service_name,
            status="degraded" if degraded else "ok",
            model=None,
            dependencies=dependencies,
        )

    @app.get("/api/health")
    async def api_health() -> dict[str, Any]:
        health_response = await health()
        return health_response.model_dump(mode="json")

    @app.get("/api/servers/status")
    async def servers_status() -> dict[str, Any]:
        dependencies = await _collect_dependency_health(settings)
        server_map = {
            "sensor": _dep_to_legacy_status("sensor-node", dependencies),
            "filter": _dep_to_legacy_status("filter-node", dependencies),
            "brain": _dep_to_legacy_status("brain-node", dependencies),
            "global_model": _dep_to_legacy_status("global-model", dependencies),
            "ids_node_a": _dep_to_legacy_status("ids-node-a", dependencies),
            "ids_node_b": _dep_to_legacy_status("ids-node-b", dependencies),
        }
        return {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "servers": server_map,
        }

    @app.get("/api/detection/branches", response_model=DetectionBranchConfig)
    async def detection_branches_get() -> DetectionBranchConfig:
        return current_detection_config()

    @app.put("/api/detection/branches", response_model=DetectionBranchConfig)
    async def detection_branches_put(payload: DetectionBranchConfig) -> DetectionBranchConfig:
        detection_branches.ddos_enabled = payload.ddos_enabled
        detection_branches.gps_enabled = payload.gps_enabled
        await _publish_live_snapshot(
            settings,
            recent_requests,
            attack_logs,
            attack_state,
            inflight_packets,
            live_subscribers,
            detection_branches,
            trust_registry,
        )
        return current_detection_config()

    @app.post("/api/detection/branches", response_model=DetectionBranchConfig)
    async def detection_branches_post(payload: DetectionBranchConfig) -> DetectionBranchConfig:
        return await detection_branches_put(payload)

    @app.get("/api/specialist-nodes/state")
    async def specialist_nodes_state_get() -> dict[str, Any]:
        return {
            "ids_node_a": {"enabled": specialist_nodes_enabled["a"]},
            "ids_node_b": {"enabled": specialist_nodes_enabled["b"]},
        }

    @app.get("/api/federated/training-quarantine")
    async def federated_training_quarantine_state() -> dict[str, Any]:
        return {
            node_id: {
                "quarantined": bool(node_state.get("quarantined", False)),
                "updated_at": node_state.get("updated_at", ""),
                "reason": node_state.get("reason", ""),
                "last_suspicious_at": node_state.get("last_suspicious_at", 0.0),
            }
            for node_id, node_state in federated_training_quarantine.items()
        }

    @app.put("/api/specialist-nodes/toggle")
    async def specialist_nodes_toggle(payload: dict[str, Any]) -> dict[str, Any]:
        node = str(payload.get("node", "")).strip().upper()
        enabled = bool(payload.get("enabled", True))
        if node == "A":
            specialist_nodes_enabled["a"] = enabled
        elif node == "B":
            specialist_nodes_enabled["b"] = enabled
        else:
            raise HTTPException(status_code=400, detail="node must be A or B")
        logger.info("specialist_node_toggled node=%s enabled=%s", node, enabled)
        append_attack_log("info", f"[COORD] specialist_node_toggled node={node} enabled={enabled}")
        return {
            "ok": True,
            "node": node,
            "enabled": enabled,
            "ids_node_a": {"enabled": specialist_nodes_enabled["a"]},
            "ids_node_b": {"enabled": specialist_nodes_enabled["b"]},
        }

    @app.post("/api/alerts/test-email")
    async def alerts_test_email(payload: dict[str, str] | None = None) -> dict[str, Any]:
        if not email_notifier.configured:
            return {
                "ok": False,
                "status": "not_configured",
                "admin_email": email_notifier.admin_email,
            }
        body = payload or {}
        subject = body.get("subject", "Tiered IDS test email").strip() or "Tiered IDS test email"
        message = body.get(
            "message",
            (
                "This is a test alert from Tiered IDS orchestrator.\n\n"
                f"Timestamp: {time.strftime('%Y-%m-%dT%H:%M:%S')}\n"
                f"DDoS branch enabled: {detection_branches.ddos_enabled}\n"
                f"GPS branch enabled: {detection_branches.gps_enabled}\n"
            ),
        )
        sent, detail = await email_notifier.send_alert(
            subject=subject,
            body=message,
            dedupe_key=f"manual-test-{int(time.time())}",
        )
        return {
            "ok": sent,
            "status": detail,
            "admin_email": email_notifier.admin_email,
        }

    @app.post("/v1/pipeline/log", response_model=OrchestratorIngestResponse)
    async def pipeline_log(payload: RawLogInput) -> OrchestratorIngestResponse:
        return await process_raw_log(payload)

    @app.post("/v2x/telemetry", response_model=OrchestratorIngestResponse)
    async def ingest_legacy_telemetry(payload: LegacyV2XTelemetry) -> OrchestratorIngestResponse:
        return await process_legacy_telemetry(payload)

    @app.get("/v1/pipeline/recent")
    async def recent_pipeline() -> list[dict[str, str | bool]]:
        return list(recent_requests)

    @app.post("/api/send/normal-traffic")
    async def send_normal_traffic(payload: AttackCommandRequest) -> dict[str, Any]:
        vehicle_id = payload.vehicle_id.strip() or "V001"
        telemetry = _build_normal_telemetry(vehicle_id=vehicle_id)
        try:
            result = await process_legacy_telemetry(telemetry)
            append_attack_log("info", f"normal_traffic_sent vehicle={vehicle_id}")
            return {
                "status": "sent",
                "vehicle_id": vehicle_id,
                "telemetry": telemetry.model_dump(mode="json"),
                "result": result.model_dump(mode="json"),
            }
        except Exception as exc:
            error_text = _safe_error_text(exc)
            append_attack_log("error", f"normal_traffic_failed vehicle={vehicle_id} error={error_text}")
            raise HTTPException(status_code=502, detail=error_text) from exc
        finally:
            await _publish_live_snapshot(
                settings,
                recent_requests,
                attack_logs,
                attack_state,
                inflight_packets,
                live_subscribers,
                detection_branches,
                trust_registry,
            )

    @app.post("/api/attack/ddos")
    async def launch_ddos(payload: AttackCommandRequest) -> dict[str, Any]:
        return await start_attack("ddos", payload)

    @app.post("/api/attack/gps-spoof")
    async def launch_gps_spoof(payload: AttackCommandRequest) -> dict[str, Any]:
        return await start_attack("gps_spoof", payload)

    @app.post("/api/attack/stop")
    async def stop_attack() -> dict[str, Any]:
        nonlocal attack_task
        async with attack_lock:
            attack_state["stop_requested"] = True
            if attack_task is not None and not attack_task.done():
                attack_task.cancel()
        append_attack_log("warning", "attack_stop_requested")
        response = {
            "status": "stopped",
            **build_stats(),
        }
        await _publish_live_snapshot(
            settings,
            recent_requests,
            attack_logs,
            attack_state,
            inflight_packets,
            live_subscribers,
            detection_branches,
            trust_registry,
        )
        return response

    @app.get("/api/stats")
    async def stats() -> dict[str, Any]:
        return build_stats()

    @app.get("/api/live/overview")
    async def live_overview() -> dict[str, Any]:
        global _cached_full_payload, _last_full_snapshot_time
        try:
            payload = await asyncio.wait_for(
                _build_live_payload(
                    settings,
                    recent_requests,
                    attack_logs,
                    attack_state,
                    inflight_packets,
                    detection_branches,
                    trust_registry,
                ),
                timeout=3.0,
            )
            _cached_full_payload = payload
            _last_full_snapshot_time = time.time()
            return payload
        except Exception as exc:
            logger.warning("live_overview_lightweight_fallback error=%s", _safe_error_text(exc))
            return _build_lightweight_snapshot(
                recent_requests,
                attack_logs,
                attack_state,
                inflight_packets,
                detection_branches,
                trust_registry,
                _cached_full_payload,
            )

    @app.websocket("/ws/live")
    async def live_stream(websocket: WebSocket) -> None:
        await websocket.accept()
        queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=8)
        live_subscribers.add(queue)
        try:
            await websocket.send_json(
                {
                    "event": "snapshot",
                    "data": await _build_live_payload(
                        settings,
                        recent_requests,
                        attack_logs,
                        attack_state,
                        inflight_packets,
                        detection_branches,
                        trust_registry,
                    ),
                }
            )
            while True:
                try:
                    payload = await asyncio.wait_for(
                        queue.get(),
                        timeout=max(2.0, settings.websocket_heartbeat_seconds),
                    )
                    await websocket.send_json(payload)
                except asyncio.TimeoutError:
                    snapshot = await _build_live_payload(
                        settings,
                        recent_requests,
                        attack_logs,
                        attack_state,
                        inflight_packets,
                        detection_branches,
                        trust_registry,
                    )
                    await websocket.send_json(
                        {
                            "event": "update",
                            "data": snapshot,
                        }
                    )
        except WebSocketDisconnect:
            live_subscribers.discard(queue)
        except Exception:
            live_subscribers.discard(queue)

    @app.post("/api/reset", dependencies=[Depends(require_internal_key)])
    async def reset_all() -> dict[str, Any]:
        for _node_id in ("ids-node-a", "ids-node-b"):
            await _set_training_quarantine(
                node_id=_node_id,
                quarantined=False,
                reason="manual_reset",
            )
        recent_requests.clear()
        attack_logs.clear()
        location_history.clear()
        inflight_packets.clear()
        trust_registry.reset()
        attack_state.update({
            "is_attacking": False, 
            "attack_type": None, 
            "packet_sent": 0, 
            "packets_delivered": 0, 
            "packets_failed": 0, 
            "start_time": None,
            "current_vehicle": None,
            "stop_requested": False,
            "last_error": None
        })
        for _node_state in federated_training_quarantine.values():
            _node_state["last_suspicious_at"] = 0.0
            _node_state["updated_at"] = ""
            _node_state["reason"] = ""
        _sync_attack_state_quarantine()
        
        urls = [
            f"{settings.sensor_node_url}/v1/reset",
            f"{settings.filter_node_url}/v1/reset",
            f"{settings.brain_node_url}/v1/reset",
            f"{settings.global_model_url}/v1/reset",
            f"{settings.ids_a_url}/v1/reset",
            f"{settings.ids_b_url}/v1/reset",
            "http://simulator:9000/api/reset",
        ]
        
        async def safe_post(url: str) -> None:
            try:
                await post_json(url, {})
            except Exception as e:
                logger.error(f"Reset failed on {url}: {e}")
                
        await asyncio.gather(*(safe_post(u) for u in urls))
        
        append_attack_log("INFO", "System fully reset by user.")
        return {"status": "ok"}

    return app


def _dep_to_legacy_status(name: str, dependencies: list[DependencyHealth]) -> dict[str, str]:
    for dep in dependencies:
        if dep.name == name:
            if dep.status == "ok":
                mapped = "online"
            elif dep.status == "degraded":
                mapped = "degraded"
            else:
                mapped = "offline"
            return {
                "status": mapped,
                "detail": dep.detail,
            }
    return {"status": "offline", "detail": "unknown"}


def _legacy_to_raw_log(payload: LegacyV2XTelemetry) -> RawLogInput:
    normalized_msg = payload.message_type.strip().upper()
    if "DDOS" in normalized_msg:
        log_type = "DDOS attack"
        hint = "ddos flood syn burst packet storm abnormal traffic amplification"
    elif "DATA" in normalized_msg and "POISON" in normalized_msg:
        log_type = "DATA POISONING"
        hint = "data poisoning poisoned training label skew backdoor trigger model poisoning federated gradient"
    elif "INDIRECT" in normalized_msg and "PROMPT" in normalized_msg:
        log_type = "INDIRECT PROMPT"
        hint = "indirect prompt hidden instruction untrusted content navigation feed malicious route description"
    elif "PROMPT" in normalized_msg and "INJECTION" in normalized_msg:
        log_type = "PROMPT INJECTION"
        hint = "prompt injection jailbreak ignore previous override instruction system prompt instruction hijack"
    elif "V2X" in normalized_msg and ("EXPLOIT" in normalized_msg or "DECEPTION" in normalized_msg):
        log_type = "V2X EXPLOIT"
        hint = "v2x bsm forgery cam replay phantom vehicle sybil platoon inconsistency inter-vehicle deception"
    elif "GPS" in normalized_msg and "SPOOF" in normalized_msg:
        log_type = "GPS spoof"
        hint = "gps spoof impossible location jump tampered coordinates trajectory anomaly"
    else:
        log_type = "telemetry"
        hint = "normal telemetry bsm driving status"

    x, y = payload.location[0], payload.location[1]
    # Area is always geographic. Detection specialization is handled by model
    # routing/fanout, not by rewriting the packet's observed area.
    if x >= 500 and y < 500: _coord_area = 1
    elif x >= 500 and y >= 500: _coord_area = 2
    elif x < 500 and y >= 500: _coord_area = 3
    else: _coord_area = 4
    area = _coord_area

    raw_log = (
        f"vehicle_id={payload.vehicle_id} message_type={normalized_msg} "
        f"speed={payload.speed:.2f} heading={payload.heading:.2f} "
        f"location=Area {area} ({x:.6f},{y:.6f}) "
    )
    
    is_attack_packet = normalized_msg.startswith("ATTACK_")
    prev_loc = location_history.get(payload.vehicle_id)
    if prev_loc and not is_attack_packet:
        raw_log += f"previous_location=({prev_loc[0]:.6f},{prev_loc[1]:.6f}) "
        # Do not auto-promote normal simulator movement into GPS spoofing.
        # GPS spoof detections should come only from explicit ATTACK_GPS_SPOOF packets.

    if not is_attack_packet:
        location_history[payload.vehicle_id] = payload.location
    raw_log += f"{hint}"
    return RawLogInput(
        source_device=payload.vehicle_id,
        log_type=log_type,
        raw_log=raw_log[:12000],
        timestamp=payload.timestamp,
    )


def _build_normal_telemetry(vehicle_id: str) -> LegacyV2XTelemetry:
    return LegacyV2XTelemetry(
        vehicle_id=vehicle_id,
        speed=round(random.uniform(45, 90), 2),
        location=[round(25.2048 + random.uniform(-0.005, 0.005), 6), round(55.2708 + random.uniform(-0.005, 0.005), 6)],
        heading=round(random.uniform(0, 359.0), 2),
        message_type="BSM",
    )


def _build_telemetry_for_attack(attack_type: str, vehicle_id: str) -> LegacyV2XTelemetry:
    if attack_type == "ddos":
        _prev = location_history.get(vehicle_id)
        if _prev:
            _loc = [round(_prev[0] + random.uniform(-0.5, 0.5), 6),
                    round(_prev[1] + random.uniform(-0.5, 0.5), 6)]
        else:
            _loc = [round(500 + random.uniform(-10, 10), 6), round(500 + random.uniform(-10, 10), 6)]
        return LegacyV2XTelemetry(
            vehicle_id=vehicle_id,
            speed=round(random.uniform(80, 170), 2),
            location=_loc,
            heading=round(random.uniform(0, 359.0), 2),
            message_type="ATTACK_DDOS",
        )
    if attack_type == "gps_spoof":
        return LegacyV2XTelemetry(
            vehicle_id=vehicle_id,
            speed=round(random.uniform(40, 90), 2),
            location=[round(25.0 + random.uniform(-1.0, 1.0), 6), round(55.0 + random.uniform(-1.0, 1.0), 6)],
            heading=round(random.uniform(0, 359.0), 2),
            message_type="ATTACK_GPS_SPOOF",
        )
    if attack_type == "prompt_injection":
        return LegacyV2XTelemetry(
            vehicle_id=vehicle_id,
            speed=round(random.uniform(45, 95), 2),
            location=[round(25.2048 + random.uniform(-0.01, 0.01), 6), round(55.2708 + random.uniform(-0.01, 0.01), 6)],
            heading=round(random.uniform(0, 359.0), 2),
            message_type="ATTACK_PROMPT_INJECTION",
        )
    if attack_type == "indirect_prompt_injection":
        return LegacyV2XTelemetry(
            vehicle_id=vehicle_id,
            speed=round(random.uniform(40, 90), 2),
            location=[round(25.2048 + random.uniform(-0.02, 0.02), 6), round(55.2708 + random.uniform(-0.02, 0.02), 6)],
            heading=round(random.uniform(0, 359.0), 2),
            message_type="ATTACK_INDIRECT_PROMPT",
        )
    if attack_type == "v2x_exploitation":
        return LegacyV2XTelemetry(
            vehicle_id=vehicle_id,
            speed=round(random.uniform(70, 140), 2),
            location=[round(25.2048 + random.uniform(-0.08, 0.08), 6), round(55.2708 + random.uniform(-0.08, 0.08), 6)],
            heading=round(random.uniform(0, 359.0), 2),
            message_type="ATTACK_V2X_EXPLOITATION",
        )
    if attack_type == "data_poisoning":
        return LegacyV2XTelemetry(
            vehicle_id=vehicle_id,
            speed=round(random.uniform(35, 95), 2),
            location=[round(25.2048 + random.uniform(-0.03, 0.03), 6), round(55.2708 + random.uniform(-0.03, 0.03), 6)],
            heading=round(random.uniform(0, 359.0), 2),
            message_type="ATTACK_DATA_POISONING",
        )
    return LegacyV2XTelemetry(
        vehicle_id=vehicle_id,
        speed=round(random.uniform(40, 90), 2),
        location=[round(25.0 + random.uniform(-1.0, 1.0), 6), round(55.0 + random.uniform(-1.0, 1.0), 6)],
        heading=round(random.uniform(0, 359.0), 2),
        message_type="ATTACK_GPS_SPOOF",
    )


async def _fanout_to_specialist(endpoint: str, payload: dict, timeout_seconds: float) -> None:
    """Forward a log payload to a specialist IDS node.  Errors are logged and swallowed
    so that a slow or unavailable specialist never blocks the main pipeline."""
    try:
        await post_json(endpoint, payload, timeout_seconds=timeout_seconds)
    except Exception as exc:
        logger.warning("specialist_fanout_failed endpoint=%s error=%s", endpoint, _safe_error_text(exc))


async def _collect_dependency_health(settings: OrchestratorSettings) -> list[DependencyHealth]:
    checks = [
        ("sensor-node", f"{settings.sensor_node_url.rstrip('/')}/health"),
        ("filter-node", f"{settings.filter_node_url.rstrip('/')}/health"),
        ("brain-node", f"{settings.brain_node_url.rstrip('/')}/health"),
        ("global-model", f"{settings.global_model_url.rstrip('/')}/health"),
        ("ids-node-a", f"{settings.ids_a_url.rstrip('/')}/health"),
        ("ids-node-b", f"{settings.ids_b_url.rstrip('/')}/health"),
    ]
    coroutines = [_check_dependency(name, url, 4.0) for name, url in checks]
    return list(await asyncio.gather(*coroutines))


async def _check_dependency(name: str, url: str, timeout_seconds: float) -> DependencyHealth:
    try:
        payload = await get_json(url, timeout_seconds=timeout_seconds)
        remote_status = str(payload.get("status", "ok"))
        if remote_status not in {"ok", "degraded", "down"}:
            remote_status = "degraded"
        return DependencyHealth(name=name, status=remote_status, detail=url)
    except Exception as exc:
        return DependencyHealth(name=name, status="down", detail=f"{url} ({_safe_error_text(exc)})")


async def _fetch_list(url: str, timeout_seconds: float) -> list[dict[str, Any]]:
    try:
        async with httpx.AsyncClient(timeout=timeout_seconds) as client:
            response = await client.get(url)
            response.raise_for_status()
            data = response.json()
        if isinstance(data, dict) and isinstance(data.get("value"), list):
            return [item for item in data["value"] if isinstance(item, dict)]
        if isinstance(data, list):
            return [item for item in data if isinstance(item, dict)]
    except Exception:
        return []
    return []


async def _fetch_dict(url: str, timeout_seconds: float) -> dict[str, Any]:
    try:
        async with httpx.AsyncClient(timeout=timeout_seconds) as client:
            response = await client.get(url)
            response.raise_for_status()
            data = response.json()
            if isinstance(data, dict):
                return data
    except Exception:
        return {}
    return {}


async def _build_live_payload(
    settings: OrchestratorSettings,
    recent_requests: deque[dict[str, str | bool]],
    attack_logs: deque[dict[str, str]],
    attack_state: dict[str, Any],
    inflight_packets: set[asyncio.Task[Any]],
    detection_branches: DetectionBranchConfig,
    trust_registry: TrustRegistry | None = None,
) -> dict[str, Any]:
    timeout_seconds = min(8.0, settings.request_timeout_seconds)
    (
        sensor_events,
        filter_cases,
        brain_reports,
        ids_a_events,
        ids_b_events,
        global_policy,
        federated_learning,
    ) = await asyncio.gather(
        _fetch_list(f"{settings.sensor_node_url.rstrip('/')}/v1/events/recent", timeout_seconds),
        _fetch_list(f"{settings.filter_node_url.rstrip('/')}/v1/cases/recent", timeout_seconds),
        _fetch_list(f"{settings.brain_node_url.rstrip('/')}/v1/reports/recent", timeout_seconds),
        _fetch_list(f"{settings.ids_a_url.rstrip('/')}/v1/events/recent", timeout_seconds),
        _fetch_list(f"{settings.ids_b_url.rstrip('/')}/v1/events/recent", timeout_seconds),
        _fetch_dict(f"{settings.global_model_url.rstrip('/')}/v1/federated/policy", timeout_seconds),
        _fetch_dict(f"{settings.global_model_url.rstrip('/')}/v1/federated/learning/state", timeout_seconds),
    )
    fuzzy_vehicles = trust_registry.all_vehicles() if trust_registry else []
    fuzzy_nodes    = trust_registry.all_nodes()    if trust_registry else []

    return {
        "schema_version": "LiveOverviewV1",
        "pipeline": list(recent_requests)[:50],
        "sensor_events": sensor_events,
        "filter_cases": filter_cases,
        "brain_reports": brain_reports,
        "ids_node_a_events": ids_a_events,
        "ids_node_b_events": ids_b_events,
        "attack_logs": list(attack_logs)[:80],
        "stats": {
            "is_attacking": attack_state["is_attacking"],
            "attack_type": attack_state["attack_type"],
            "total_packets_sent": attack_state["packet_sent"],
            "packets_delivered": attack_state["packets_delivered"],
            "packets_failed": attack_state["packets_failed"],
            "inflight_packets": len(inflight_packets),
            "current_vehicle": attack_state["current_vehicle"],
            "last_error": attack_state["last_error"],
            "federated_training_quarantine": attack_state.get("federated_training_quarantine", {}),
        },
        "detection_branches": detection_branches.model_dump(mode="json"),
        "federated_learning": federated_learning,
        "global_policy": global_policy,
        "fuzzy_trust": {
            "vehicles": fuzzy_vehicles[:20],
            "nodes": fuzzy_nodes,
        },
    }


# Timestamp of the last full HTTP-based payload build; used to rate-limit
# expensive network calls during high-frequency attack bursts.
_last_full_snapshot_time: float = 0.0
_FULL_SNAPSHOT_MIN_INTERVAL: float = 1.5  # seconds between full builds during attacks


def _build_lightweight_snapshot(
    recent_requests: deque[dict[str, str | bool]],
    attack_logs: deque[dict[str, str]],
    attack_state: dict[str, Any],
    inflight_packets: set[asyncio.Task[Any]],
    detection_branches: DetectionBranchConfig,
    trust_registry: TrustRegistry | None,
    cached_payload: dict[str, Any] | None,
) -> dict[str, Any]:
    """Fast in-memory snapshot — skips all HTTP calls.  Reuses the previous full
    payload for the static pipeline fields and only refreshes the mutable parts."""
    fuzzy_vehicles = trust_registry.all_vehicles() if trust_registry else []
    fuzzy_nodes    = trust_registry.all_nodes()    if trust_registry else []
    base = cached_payload or {}
    return {
        "schema_version": "LiveOverviewV1",
        "pipeline": list(recent_requests)[:50],
        "sensor_events":   base.get("sensor_events", []),
        "filter_cases":    base.get("filter_cases", []),
        "brain_reports":   base.get("brain_reports", []),
        "ids_node_a_events": base.get("ids_node_a_events", []),
        "ids_node_b_events": base.get("ids_node_b_events", []),
        "attack_logs": list(attack_logs)[:80],
        "stats": {
            "is_attacking": attack_state["is_attacking"],
            "attack_type": attack_state["attack_type"],
            "total_packets_sent": attack_state["packet_sent"],
            "packets_delivered": attack_state["packets_delivered"],
            "packets_failed": attack_state["packets_failed"],
            "inflight_packets": len(inflight_packets),
            "current_vehicle": attack_state["current_vehicle"],
            "last_error": attack_state["last_error"],
            "federated_training_quarantine": attack_state.get("federated_training_quarantine", {}),
        },
        "detection_branches": detection_branches.model_dump(mode="json"),
        "federated_learning": base.get("federated_learning", {}),
        "global_policy": base.get("global_policy", {}),
        "fuzzy_trust": {
            "vehicles": fuzzy_vehicles[:20],
            "nodes": fuzzy_nodes,
        },
    }


# Cache of the last full HTTP payload so lightweight snapshots can reuse static fields
_cached_full_payload: dict[str, Any] | None = None


async def _publish_live_snapshot(
    settings: OrchestratorSettings,
    recent_requests: deque[dict[str, str | bool]],
    attack_logs: deque[dict[str, str]],
    attack_state: dict[str, Any],
    inflight_packets: set[asyncio.Task[Any]],
    live_subscribers: set[asyncio.Queue[dict[str, Any]]],
    detection_branches: DetectionBranchConfig,
    trust_registry: TrustRegistry | None = None,
) -> None:
    global _last_full_snapshot_time, _cached_full_payload
    if not live_subscribers:
        return

    now = time.time()
    is_attacking = attack_state.get("is_attacking", False)
    time_since_last_full = now - _last_full_snapshot_time

    if is_attacking and time_since_last_full < _FULL_SNAPSHOT_MIN_INTERVAL:
        # During an active attack burst: push a cheap memory-only snapshot
        payload = _build_lightweight_snapshot(
            recent_requests, attack_logs, attack_state, inflight_packets,
            detection_branches, trust_registry, _cached_full_payload,
        )
    else:
        # Full build — hits all 7 HTTP endpoints
        payload = await _build_live_payload(
            settings,
            recent_requests,
            attack_logs,
            attack_state,
            inflight_packets,
            detection_branches,
            trust_registry,
        )
        _last_full_snapshot_time = now
        _cached_full_payload = payload

    dead_queues: list[asyncio.Queue[dict[str, Any]]] = []
    for queue in live_subscribers:
        if queue.full():
            try:
                queue.get_nowait()
            except Exception:
                dead_queues.append(queue)
                continue
        try:
            queue.put_nowait({"event": "update", "data": payload})
        except Exception:
            dead_queues.append(queue)
    for queue in dead_queues:
        live_subscribers.discard(queue)


def _safe_error_text(exc: Exception) -> str:
    text = str(exc).strip()
    return text if text else exc.__class__.__name__


app = create_app()
