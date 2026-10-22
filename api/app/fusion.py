import json

from app.models import AnalysisRun, Evidence


def assess_case(evidence_rows: list[Evidence], analysis_runs: list[AnalysisRun]) -> dict:
    evidence_by_id = {evidence.id: evidence for evidence in evidence_rows}
    latest_by_evidence = {}
    for run in analysis_runs:
        if run.evidence_id in evidence_by_id and run.evidence_id not in latest_by_evidence:
            latest_by_evidence[run.evidence_id] = run
    relevant = list(latest_by_evidence.values())
    cue_categories: set[str] = set()
    duplicates = 0
    known_matches = 0
    repeated_senders = 0
    for run in relevant:
        signals = json.loads(run.signals_json)
        language = signals.get("language", {})
        cue_categories.update(
            cue["category"]
            for cue in language.get("language_cue_categories", [])
            if isinstance(cue, dict) and "category" in cue
        )
        duplicates += len(signals.get("visual", {}).get("duplicate_candidates", []))
        known_matches += int(bool(signals.get("known_hash", {}).get("match")))
        repeated_senders += len(signals.get("behavior", {}).get("repeated_senders", []))

    components = {
        "language_pattern_cues": {
            "weight": 0.55,
            "observed": len(cue_categories),
            "contribution": round(min(len(cue_categories) / 3, 1) * 0.55, 3),
        },
        "repeated_sender_pattern": {
            "weight": 0.15,
            "observed": repeated_senders,
            "contribution": 0.15 if repeated_senders else 0.0,
        },
        "visual_duplicate_reuse": {
            "weight": 0.2,
            "observed": duplicates,
            "contribution": 0.2 if duplicates else 0.0,
        },
        "local_synthetic_fixture_match": {
            "weight": 0.1,
            "observed": known_matches,
            "contribution": 0.1 if known_matches else 0.0,
        },
    }
    score = round(min(sum(item["contribution"] for item in components.values()), 1), 3)
    tier = "HIGH" if score >= 0.7 else "AMBIGUOUS" if score >= 0.25 else "LOW"
    return {
        "score": score,
        "tier": tier,
        "components": components,
        "signals_analyzed": len(relevant),
        "evidence_count": len(evidence_rows),
        "explanation": (
            "This weighted score only prioritizes human review. It does not classify a person or "
            "item, establish wrongdoing, send a report, or take any action; there is no automatic action. Each component is "
            "shown so an investigator can interpret or disregard it."
        ),
        "review_required": True,
    }
