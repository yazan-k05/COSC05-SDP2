# AI Training Playbook

This document explains how to define new hack scenarios, run autonomous red-team
exercises, and collect training data for future models. It complements the
in-browser **AI Training Lab** (`ai_training_lab.html`) and the backend
coordinator introduced in `ai_lab.py`.

---

## 1. Scenario Anatomy

Each scenario describes three components:

| Field | Description |
| ----- | ----------- |
| `attack_chain` | Ordered list of steps the sub-AI (attacker) will attempt. |
| `telemetry_focus` | Signals the Guardian should pay attention to when it prepares a fix. |
| `hardening_goals` | Expected remediation actions for the master AI to produce. |

Scenarios live in `training_scenarios.json`. Example entry:

```jsonc
{
  "id": "SQL-FLOOD",
  "title": "SQL Filter Flood",
  "vector": "SQL Injection",
  "attack_chain": [
    "Enumerate /api/reports filter parameter",
    "Inject OR 1=1 payload to bypass tenant filter",
    "Dump audit table"
  ],
  "telemetry_focus": [
    "reporting-api filter anomalies",
    "Database connection spike",
    "IDS signature 2201"
  ],
  "hardening_goals": [
    "Parameterize query builders",
    "Add tenant-level RLS",
    "Backfill audit trail"
  ]
}
```

Add new scenarios by extending this JSON file—no code changes required unless
you need additional metadata.

---

## 2. Running Offline Training

The `ai_trainer.py` utility wires the environment, attacker, and Guardian
together. It performs the following loop:

1. Load a scenario definition.
2. Run reconnaissance (`LabAttackerAgent.scan()`).
3. Execute a simulated exploit.
4. Ask the Guardian (local GPT4All instance) for a targeted patch plan.
5. Apply the patch via `LabCoordinator.apply_patch`.
6. Persist a structured log (`training_logs/<timestamp>_<scenario>.json`).

Usage:

```bash
python ai_trainer.py --scenario SQL-FLOOD
python ai_trainer.py --scenario TOKEN-BLIND --episodes 5
```

Use `--list` to print all available scenarios.

---

## 3. Expanding the Vulnerability Pool

`ai_lab.py` defines the sandbox vulnerabilities. To test new ideas:

1. Add a `Vulnerability` entry in `LabEnvironment.__init__`.
2. Provide realistic hints to help the sub-AI find it.
3. Optionally extend the web UI to surface the new weakness.

The attacker uses heuristic confidence scores, so even simple hints create a
believable workflow.

---

## 4. Integrating With Models

Collected training logs contain:

* Scenario metadata.
* Recon clues the attacker used.
* Exploit vectors and severities.
* Guardian patch plans (LLM-generated).

Use these JSON records as supervised examples for future models:

```python
import json, glob

dataset = []
for path in glob.glob('training_logs/*.json'):
    with open(path) as fp:
        dataset.append(json.load(fp))
```

Each record includes both the offensive narrative and the defensive response,
making it a strong candidate for instruction tuning or RAG pipelines.

---

## 5. Recommended Workflow

1. **Design** a new scenario in `training_scenarios.json`.
2. **Simulate** it in-browser via the AI Training Lab.
3. **Automate** runs with `ai_trainer.py --episodes N`.
4. **Review** `training_logs/` and feed them into your preferred training stack
   (LoRA, adapters, or external fine-tuning service).

This keeps everything local/right-sized while allowing the Guardian to evolve
with the network. Feel free to tailor the scenarios or extend the trainer for
more sophisticated behaviors (e.g., reward functions, curriculum learning).

