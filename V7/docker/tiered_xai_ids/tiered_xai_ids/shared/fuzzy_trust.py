"""
Fuzzy logic trust engine — vehicular IDS coordination layer.

Computes an adaptive trust score [0, 1] for each entity (vehicle or fog/IDS node)
using a Mamdani fuzzy inference system with weighted-average defuzzification.

Inputs
------
  confidence      [0,1]  EMA of LLM output certainty for this entity's traffic
  anomaly_score   [0,1]  EMA of per-event anomaly deviation (0=clean, 1=attack)
  success_rate    [0,1]  rolling packet delivery / response reliability
  attack_exposure [0,1]  current attack load on this node (rises under attack, decays when clear)

Output
------
  trust_score [0,1]  — higher is more trusted
  trust_label        — UNTRUSTED / LOW / UNCERTAIN / TRUSTED / HIGHLY_TRUSTED
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

TrustLabel = Literal["UNTRUSTED", "LOW", "UNCERTAIN", "TRUSTED", "HIGHLY_TRUSTED"]

# ---------------------------------------------------------------------------
# Membership functions
# ---------------------------------------------------------------------------

def _trap(x: float, a: float, b: float, c: float, d: float) -> float:
    """Trapezoid MF — full membership on [b, c], linear slopes on [a,b] and [c,d].
    Uses open boundaries at a and d so degenerate shoulders (a==b or c==d) work correctly."""
    if x < a or x > d:
        return 0.0
    if b <= x <= c:
        return 1.0
    if x < b:
        return (x - a) / (b - a) if b > a else 1.0
    return (d - x) / (d - c) if d > c else 1.0


def _tri(x: float, a: float, b: float, c: float) -> float:
    """Triangle MF — peak at b, zero at a and c."""
    if x <= a or x >= c:
        return 0.0
    if x <= b:
        return (x - a) / (b - a) if b != a else 1.0
    return (c - x) / (c - b) if c != b else 1.0


# Three linguistic levels for all inputs
def _lo(x: float) -> float:   return _trap(x, 0.00, 0.00, 0.25, 0.50)
def _md(x: float) -> float:   return _tri(x,  0.25, 0.50, 0.75)
def _hi(x: float) -> float:   return _trap(x, 0.50, 0.75, 1.00, 1.00)


# ---------------------------------------------------------------------------
# Core inference
# ---------------------------------------------------------------------------

@dataclass
class FuzzyTrustInput:
    confidence: float       # [0,1]
    anomaly_score: float    # [0,1]
    success_rate: float     # [0,1]
    attack_exposure: float  # [0,1]


@dataclass
class FuzzyTrustResult:
    trust_score: float
    trust_label: TrustLabel
    membership: dict[str, float]
    firing_strengths: dict[str, float]


# Output singleton centroids (Mamdani singletons)
_OUT = {"untrusted": 0.08, "low": 0.28, "uncertain": 0.50, "trusted": 0.72, "high_trust": 0.92}


def compute_trust(inp: FuzzyTrustInput) -> FuzzyTrustResult:
    c  = max(0.0, min(1.0, float(inp.confidence)))
    a  = max(0.0, min(1.0, float(inp.anomaly_score)))
    s  = max(0.0, min(1.0, float(inp.success_rate)))
    ae = max(0.0, min(1.0, float(inp.attack_exposure)))

    c_lo, c_md, c_hi   = _lo(c),  _md(c),  _hi(c)
    a_lo, a_md, a_hi   = _lo(a),  _md(a),  _hi(a)
    s_lo, s_md, s_hi   = _lo(s),  _md(s),  _hi(s)
    ae_lo, ae_md, ae_hi = _lo(ae), _md(ae), _hi(ae)

    # Each rule: (firing_strength, output_centroid, label)
    rules: list[tuple[float, float, str]] = [
        # --- Strong positive signals ---
        (min(c_hi, a_lo, s_hi),      _OUT["high_trust"],  "R01:HiConf+LoAnom+HiSucc→HighlyTrusted"),
        (min(c_hi, a_lo, s_md),      _OUT["trusted"],     "R02:HiConf+LoAnom+MdSucc→Trusted"),
        (min(c_md, a_lo, s_hi),      _OUT["trusted"],     "R03:MdConf+LoAnom+HiSucc→Trusted"),
        (min(c_md, a_lo, s_md),      _OUT["trusted"],     "R04:MdConf+LoAnom+MdSucc→Trusted"),
        # --- Low exposure boost ---
        (min(s_hi, ae_lo),           _OUT["trusted"],     "R05:HiSucc+LoExposure→Trusted"),
        # --- Ambiguous / medium signals ---
        (min(c_hi, a_md),            _OUT["uncertain"],   "R06:HiConf+MdAnom→Uncertain"),
        (min(c_lo, a_lo),            _OUT["uncertain"],   "R07:LoConf+LoAnom→Uncertain"),
        (min(c_md, a_md),            _OUT["uncertain"],   "R08:MdConf+MdAnom→Uncertain"),
        # --- Degradation under attack ---
        (ae_hi,                      _OUT["untrusted"],   "R09:HiExposure→Untrusted"),
        (min(ae_md, a_hi),           _OUT["untrusted"],   "R10:MdExposure+HiAnom→Untrusted"),
        (min(ae_md, a_md),           _OUT["low"],         "R11:MdExposure+MdAnom→Low"),
        # --- Anomaly-driven degradation ---
        (a_hi,                       _OUT["low"],         "R12:HiAnom→Low"),
        (min(c_lo, a_md),            _OUT["low"],         "R13:LoConf+MdAnom→Low"),
        # --- Low success rate ---
        (s_lo,                       _OUT["low"],         "R14:LoSuccRate→Low"),
        (min(s_lo, a_hi),            _OUT["untrusted"],   "R15:LoSucc+HiAnom→Untrusted"),
    ]

    num = sum(fs * oc for fs, oc, _ in rules)
    den = sum(fs         for fs, _,  _ in rules)
    score = num / den if den > 1e-9 else 0.5

    firing = {name: round(fs, 4) for fs, _, name in rules if fs > 0.005}

    membership = {
        "c_lo": round(c_lo, 3),   "c_md": round(c_md, 3),   "c_hi": round(c_hi, 3),
        "a_lo": round(a_lo, 3),   "a_md": round(a_md, 3),   "a_hi": round(a_hi, 3),
        "s_lo": round(s_lo, 3),   "s_md": round(s_md, 3),   "s_hi": round(s_hi, 3),
        "ae_lo": round(ae_lo, 3), "ae_md": round(ae_md, 3), "ae_hi": round(ae_hi, 3),
    }

    if score >= 0.78:
        label: TrustLabel = "HIGHLY_TRUSTED"
    elif score >= 0.58:
        label = "TRUSTED"
    elif score >= 0.38:
        label = "UNCERTAIN"
    elif score >= 0.20:
        label = "LOW"
    else:
        label = "UNTRUSTED"

    return FuzzyTrustResult(
        trust_score=round(score, 4),
        trust_label=label,
        membership=membership,
        firing_strengths=firing,
    )


# ---------------------------------------------------------------------------
# Stateful per-entity tracker (EMA smoothing)
# ---------------------------------------------------------------------------

@dataclass
class TrustTracker:
    entity_id: str
    entity_type: Literal["vehicle", "fog_node", "ids_node"]

    _conf_ema: float = field(default=0.50, repr=False)
    _anom_ema: float = field(default=0.10, repr=False)
    _succ_rate: float = field(default=1.00, repr=False)
    _exposure: float = field(default=0.00, repr=False)
    # Once a vehicle/node has been confirmed malicious, its trust can never fully recover.
    # The ceiling ratchets down on each attack burst and never rises again.
    _trust_ceiling: float = field(default=1.0, repr=False)

    _total_seen: int = field(default=0, repr=False)
    _total_suspicious: int = field(default=0, repr=False)
    _total_attacks: int = field(default=0, repr=False)

    last_result: FuzzyTrustResult | None = field(default=None, repr=False)

    # EMA smoothing — higher α means faster response to new evidence
    _ALPHA: float = field(default=0.35, repr=False, init=False)
    # Attack exposure: rises sharply per suspicious packet, decays slowly when clear
    _EXP_RISE: float = field(default=0.25, repr=False, init=False)
    _EXP_DECAY: float = field(default=0.04, repr=False, init=False)

    def update(
        self,
        *,
        confidence: float | None = None,
        anomaly_score: float | None = None,
        is_suspicious: bool = False,
        delivered: bool = True,
        under_attack: bool = False,
    ) -> FuzzyTrustResult:
        self._total_seen += 1
        if is_suspicious:
            self._total_suspicious += 1

        if confidence is not None:
            self._conf_ema = self._ALPHA * confidence + (1 - self._ALPHA) * self._conf_ema
        if anomaly_score is not None:
            self._anom_ema = self._ALPHA * anomaly_score + (1 - self._ALPHA) * self._anom_ema

        delivered_f = 1.0 if delivered else 0.0
        self._succ_rate = self._ALPHA * delivered_f + (1 - self._ALPHA) * self._succ_rate

        if under_attack:
            self._total_attacks += 1
            self._exposure = min(1.0, self._exposure + self._EXP_RISE)
        else:
            self._exposure = max(0.0, self._exposure - self._EXP_DECAY)

        inp = FuzzyTrustInput(
            confidence=self._conf_ema,
            anomaly_score=self._anom_ema,
            success_rate=self._succ_rate,
            attack_exposure=self._exposure,
        )
        result = compute_trust(inp)

        # Ratchet ceiling down whenever this entity is confirmed malicious.
        # The ceiling can only decrease — trust is permanently stained after attacks.
        if under_attack and result.trust_score < self._trust_ceiling:
            # Lock the ceiling at most 0.05 above the current compromised score
            self._trust_ceiling = min(self._trust_ceiling, max(0.30, result.trust_score + 0.05))

        # Clamp the score so a recovered (clean-traffic) entity can never surpass
        # the ceiling it earned while misbehaving.
        clamped_score = min(result.trust_score, self._trust_ceiling)
        if clamped_score != result.trust_score:
            # Recompute label for the clamped score
            if clamped_score >= 0.78:
                clamped_label: TrustLabel = "HIGHLY_TRUSTED"
            elif clamped_score >= 0.58:
                clamped_label = "TRUSTED"
            elif clamped_score >= 0.38:
                clamped_label = "UNCERTAIN"
            elif clamped_score >= 0.20:
                clamped_label = "LOW"
            else:
                clamped_label = "UNTRUSTED"
            result = FuzzyTrustResult(
                trust_score=round(clamped_score, 4),
                trust_label=clamped_label,
                membership=result.membership,
                firing_strengths=result.firing_strengths,
            )

        self.last_result = result
        return self.last_result

    def to_dict(self) -> dict:
        r = self.last_result
        return {
            "entity_id": self.entity_id,
            "entity_type": self.entity_type,
            "trust_score": r.trust_score if r else 0.50,
            "trust_label": r.trust_label if r else "UNCERTAIN",
            "trust_ceiling": round(self._trust_ceiling, 4),
            "confidence_ema": round(self._conf_ema, 4),
            "anomaly_ema": round(self._anom_ema, 4),
            "success_rate": round(self._succ_rate, 4),
            "attack_exposure": round(self._exposure, 4),
            "total_seen": self._total_seen,
            "total_suspicious": self._total_suspicious,
            "total_attacks": self._total_attacks,
            "firing_strengths": r.firing_strengths if r else {},
        }


# ---------------------------------------------------------------------------
# Registry — holds all tracked entities
# ---------------------------------------------------------------------------

class TrustRegistry:
    def __init__(self) -> None:
        self._store: dict[str, TrustTracker] = {}

    def _get_or_create(
        self,
        entity_id: str,
        entity_type: Literal["vehicle", "fog_node", "ids_node"],
    ) -> TrustTracker:
        if entity_id not in self._store:
            self._store[entity_id] = TrustTracker(
                entity_id=entity_id,
                entity_type=entity_type,
            )
        return self._store[entity_id]

    def update_vehicle(
        self,
        vehicle_id: str,
        *,
        confidence: float,
        anomaly_score: float,
        is_suspicious: bool,
        delivered: bool = True,
    ) -> FuzzyTrustResult:
        tracker = self._get_or_create(vehicle_id, "vehicle")
        # A vehicle sending suspicious/malicious traffic is itself "under attack
        # mode" — raise its attack_exposure so rules R09/R10/R11 fire and trust
        # degrades visibly each packet instead of only through slow EMA drift.
        return tracker.update(
            confidence=confidence,
            anomaly_score=anomaly_score,
            is_suspicious=is_suspicious,
            delivered=delivered,
            under_attack=is_suspicious,
        )

    def update_node(
        self,
        node_id: str,
        entity_type: Literal["fog_node", "ids_node"],
        *,
        under_attack: bool,
        delivered: bool = True,
        confidence: float | None = None,
        anomaly_score: float | None = None,
    ) -> FuzzyTrustResult:
        tracker = self._get_or_create(node_id, entity_type)
        return tracker.update(
            confidence=confidence,
            anomaly_score=anomaly_score,
            delivered=delivered,
            under_attack=under_attack,
        )

    def all_vehicles(self) -> list[dict]:
        return [
            t.to_dict()
            for t in sorted(self._store.values(), key=lambda t: -(t.last_result.trust_score if t.last_result else 0.5))
            if t.entity_type == "vehicle"
        ]

    def all_nodes(self) -> list[dict]:
        return [
            t.to_dict()
            for t in self._store.values()
            if t.entity_type in ("fog_node", "ids_node")
        ]

    def reset(self) -> None:
        self._store.clear()
