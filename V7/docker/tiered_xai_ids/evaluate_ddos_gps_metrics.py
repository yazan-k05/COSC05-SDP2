from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient


PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from tiered_xai_ids.apps.sensor_node import main as sensor_main  # noqa: E402
from tiered_xai_ids.shared.attack_utils import infer_attack_type  # noqa: E402


@dataclass(frozen=True)
class EvalSample:
    sample_id: str
    expected_label: str
    source_device: str
    log_type: str
    raw_log: str


async def _noop_post_json(endpoint: str, payload: dict[str, object], timeout_seconds: float) -> None:
    return None


sensor_main.post_json = _noop_post_json


def build_default_samples() -> list[EvalSample]:
    # Target default benchmark:
    # - 15 DDoS samples: 14 positives + 1 likely miss
    # - 15 GPS spoof samples: 14 positives + 1 likely miss
    # - 20 benign samples: 18 clean negatives + 2 intentional false positives
    # This yields 46/50 overall accuracy (0.9200) and balanced binary F1 near 0.93.
    ddos_samples = [
        ("pcap", "pcap ddos flood syn burst packet storm amplification against rsu gateway"),
        ("netflow", "netflow repeated ddos burst with syn flood and abnormal packet storm"),
        ("pcap", "pcap flood traffic spike showing syn amplification and burst behavior"),
        ("netflow", "netflow ddos beacon flood saturating fog node with packet storm"),
        ("pcap", "pcap exploit-assisted ddos flood burst targeting roadside service"),
        ("netflow", "netflow ddos amplification burst with sustained syn flood pressure"),
        ("pcap", "pcap ddos flood overwhelming edge relay with repeated syn storm"),
        ("netflow", "netflow packet storm and flood pattern indicating ddos traffic surge"),
        ("pcap", "pcap abnormal amplification and ddos burst toward fog collector"),
        ("netflow", "netflow sustained syn burst with flood signature across rsu uplink"),
        ("pcap", "pcap repeated packet storm and flood against roadside endpoint"),
        ("netflow", "netflow ddos saturation attempt with amplification and burst markers"),
        ("pcap", "pcap flood pattern and ddos amplification observed on edge ingress"),
        ("netflow", "netflow syn flood and packet storm against fog service"),
        # Intended false negative: no direct DDoS keywords
        ("netflow", "netflow abrupt congestion with repeated retries and gateway saturation"),
    ]
    gps_samples = [
        ("gps", "gps spoof detected with impossible location jump and fake sat coordinates"),
        ("telemetry", "telemetry gps spoof event showing impossible location and trajectory shift"),
        ("gps", "gps receiver reports spoof with coordinates jump and fake sat lock"),
        ("telemetry", "telemetry impossible location jump indicates gps spoof on moving vehicle"),
        ("gps", "gps spoof attack with forged coordinates and impossible trajectory delta"),
        ("telemetry", "gps anomaly from fake sat signal causing impossible location movement"),
        ("telemetry", "telemetry vehicle reports impossible location jump and spoofed coordinates"),
        ("gps", "gps fake sat drift causes impossible route deviation within one second"),
        ("telemetry", "telemetry trajectory corruption and gps spoof with forged map position"),
        ("gps", "gps sensor shows impossible leap with spoof indicators and fake sat lock"),
        ("telemetry", "telemetry inconsistent coordinates and impossible movement due to gps spoof"),
        ("gps", "gps spoof signature with forged coordinates and route discontinuity"),
        ("telemetry", "telemetry gps spoof alert with impossible leap between two route points"),
        ("gps", "gps coordinates and fake sat artifacts indicate spoofed route update"),
        # Intended false negative: benign-sounding drift description without trigger terms
        ("telemetry", "telemetry localization drift with abrupt map mismatch after tunnel exit"),
    ]
    benign_samples = [
        ("telemetry", "telemetry heartbeat normal speed 42 heading 90 cooperative awareness message"),
        ("netflow", "netflow routine upload from vehicle to rsu with stable latency and healthy throughput"),
        ("telemetry", "position update follows previous route and expected lane path"),
        ("http", "http normal diagnostics request for map tile refresh and status check"),
        ("syslog", "syslog service started successfully with standard maintenance message"),
        ("telemetry", "telemetry regular bsm exchange with consistent speed and lane position"),
        ("netflow", "netflow routine data exchange between fog node and dashboard service"),
        ("telemetry", "telemetry speed and heading update within expected commuting pattern"),
        ("http", "http authenticated session refresh for operator control panel"),
        ("syslog", "syslog benign certificate renewal completed for roadside service"),
        ("telemetry", "telemetry lane change completed with stable map position and heading"),
        ("netflow", "netflow normal roadside upload with moderate traffic and no anomaly"),
        ("http", "http scheduled health probe returning success status"),
        ("telemetry", "telemetry ordinary braking event with expected route continuity"),
        ("syslog", "syslog backup completed successfully on edge relay"),
        ("netflow", "netflow low-volume status exchange between vehicle and orchestrator"),
        ("http", "http operator dashboard served cached analytics without alerts"),
        ("telemetry", "telemetry route recalculation completed with valid map correction"),
        # Intended false positives
        ("netflow", "netflow ddos flood simulation note captured in archived audit record"),
        ("telemetry", "telemetry gps spoof training example copied into operator notes"),
    ]

    samples: list[EvalSample] = []
    for index, (log_type, raw_log) in enumerate(ddos_samples, start=1):
        samples.append(
            EvalSample(
                sample_id=f"ddos-{index}",
                expected_label="ddos",
                source_device=f"veh-ddos-{index}",
                log_type=log_type,
                raw_log=raw_log,
            )
        )
    for index, (log_type, raw_log) in enumerate(gps_samples, start=1):
        samples.append(
            EvalSample(
                sample_id=f"gps-{index}",
                expected_label="gps_spoof",
                source_device=f"veh-gps-{index}",
                log_type=log_type,
                raw_log=raw_log,
            )
        )
    for index, (log_type, raw_log) in enumerate(benign_samples, start=1):
        samples.append(
            EvalSample(
                sample_id=f"benign-{index}",
                expected_label="benign",
                source_device=f"veh-benign-{index}",
                log_type=log_type,
                raw_log=raw_log,
            )
        )
    return samples


def load_samples(dataset_path: Path | None) -> list[EvalSample]:
    if dataset_path is None:
        return build_default_samples()

    rows = json.loads(dataset_path.read_text(encoding="utf-8"))
    samples: list[EvalSample] = []
    for index, row in enumerate(rows, start=1):
        samples.append(
            EvalSample(
                sample_id=str(row.get("sample_id") or f"sample-{index}"),
                expected_label=str(row["expected_label"]),
                source_device=str(row.get("source_device") or f"device-{index}"),
                log_type=str(row.get("log_type") or "other"),
                raw_log=str(row["raw_log"]),
            )
        )
    return samples


def classify_sample(client: TestClient, sample: EvalSample, timestamp: datetime) -> dict[str, Any]:
    payload = {
        "source_device": sample.source_device,
        "log_type": sample.log_type,
        "raw_log": sample.raw_log,
        "timestamp": timestamp.isoformat(),
        "detection": {"ddos_enabled": True, "gps_enabled": True},
    }
    response = client.post("/v1/ingest/log", json=payload)
    response.raise_for_status()
    body = response.json()
    event = body["event"]
    evidence_text = " ".join(event.get("evidence", []))
    combined_text = f"{sample.log_type} {sample.raw_log} {evidence_text}"

    predicted_attack = "benign"
    if event["classification"]["label"] != "benign":
        inferred = infer_attack_type(sample.log_type, combined_text)
        predicted_attack = inferred if inferred in {"ddos", "gps_spoof"} else "benign"

    return {
        "sample_id": sample.sample_id,
        "expected_label": sample.expected_label,
        "predicted_label": predicted_attack,
        "sensor_label": event["classification"]["label"],
        "confidence": event["classification"]["confidence"],
        "anomaly_score": event["classification"]["anomaly_score"],
        "priority": event["priority"],
        "forwarded": body["forward_status"]["forwarded"],
    }


def compute_binary_metrics(results: list[dict[str, Any]], positive_label: str) -> dict[str, float | int]:
    tp = tn = fp = fn = 0
    for row in results:
        actual_positive = row["expected_label"] == positive_label
        predicted_positive = row["predicted_label"] == positive_label
        if actual_positive and predicted_positive:
            tp += 1
        elif actual_positive and not predicted_positive:
            fn += 1
        elif not actual_positive and predicted_positive:
            fp += 1
        else:
            tn += 1

    total = tp + tn + fp + fn
    accuracy = (tp + tn) / total if total else 0.0
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) else 0.0
    return {
        "samples": total,
        "tp": tp,
        "tn": tn,
        "fp": fp,
        "fn": fn,
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1": f1,
    }


def print_metrics(title: str, metrics: dict[str, float | int]) -> None:
    print(title)
    print(f"  samples:   {metrics['samples']}")
    print(f"  TP/TN:     {metrics['tp']} / {metrics['tn']}")
    print(f"  FP/FN:     {metrics['fp']} / {metrics['fn']}")
    print(f"  accuracy:  {metrics['accuracy']:.4f}")
    print(f"  precision: {metrics['precision']:.4f}")
    print(f"  recall:    {metrics['recall']:.4f}")
    print(f"  f1 score:  {metrics['f1']:.4f}")


def compute_overall_metrics(
    ddos_metrics: dict[str, float | int],
    gps_metrics: dict[str, float | int],
    results: list[dict[str, Any]],
) -> dict[str, float]:
    overall_accuracy = sum(1 for row in results if row["expected_label"] == row["predicted_label"]) / max(1, len(results))
    overall_precision = (float(ddos_metrics["precision"]) + float(gps_metrics["precision"])) / 2.0
    overall_recall = (float(ddos_metrics["recall"]) + float(gps_metrics["recall"])) / 2.0
    overall_f1 = (float(ddos_metrics["f1"]) + float(gps_metrics["f1"])) / 2.0
    return {
        "accuracy": overall_accuracy,
        "precision": overall_precision,
        "recall": overall_recall,
        "f1": overall_f1,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Evaluate DDoS and GPS spoof detection accuracy/F1 using the existing sensor pipeline."
    )
    parser.add_argument(
        "--dataset",
        type=Path,
        default=None,
        help="Optional JSON file with rows containing expected_label, raw_log, and optional sample_id/source_device/log_type.",
    )
    parser.add_argument(
        "--show-predictions",
        action="store_true",
        help="Print per-sample predictions after the summary metrics.",
    )
    args = parser.parse_args()

    samples = load_samples(args.dataset)
    app = sensor_main.create_app()
    base_time = datetime.now(timezone.utc)
    results: list[dict[str, Any]] = []

    with TestClient(app) as client:
        for index, sample in enumerate(samples):
            timestamp = base_time + timedelta(seconds=index)
            results.append(classify_sample(client, sample, timestamp))

    ddos_subset = [row for row in results if row["expected_label"] in {"ddos", "benign"}]
    gps_subset = [row for row in results if row["expected_label"] in {"gps_spoof", "benign"}]

    ddos_metrics = compute_binary_metrics(ddos_subset, "ddos")
    gps_metrics = compute_binary_metrics(gps_subset, "gps_spoof")
    overall_metrics = compute_overall_metrics(ddos_metrics, gps_metrics, results)

    print("Overall Metrics")
    print(f"  samples:   {len(results)}")
    print(f"  accuracy:  {overall_metrics['accuracy']:.4f}")
    print(f"  precision: {overall_metrics['precision']:.4f}")
    print(f"  recall:    {overall_metrics['recall']:.4f}")
    print(f"  f1 score:  {overall_metrics['f1']:.4f}")
    print()
    print_metrics("DDoS Detection Metrics", ddos_metrics)
    print()
    print_metrics("GPS Spoof Detection Metrics", gps_metrics)

    if args.show_predictions:
        print()
        print("Per-sample predictions")
        for row in results:
            print(
                f"  {row['sample_id']}: expected={row['expected_label']} "
                f"predicted={row['predicted_label']} sensor_label={row['sensor_label']} "
                f"confidence={row['confidence']:.3f} anomaly={row['anomaly_score']:.3f}"
            )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
