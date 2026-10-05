"""
MITRE ATT&CK for ICS threat intelligence — actor profiles grounded in public
reporting (attribution-update version from garima's repo).

Sources per actor:
  Xenotime/TEMP.Veles — MITRE G0088  https://attack.mitre.org/groups/G0088/
  Sandworm Team       — MITRE G0034  https://attack.mitre.org/groups/G0034/
  Volt Typhoon        — MITRE G1017  https://attack.mitre.org/groups/G1017/
  ALLANITE            — Dragos / MITRE ICS group knowledge base
"""

MITRE_TECHNIQUES = [
    {"id": "T0855", "name": "Unauthorized Command Message",       "tactic": "Inhibit Response Function"},
    {"id": "T0836", "name": "Modify Parameter",                   "tactic": "Impair Process Control"},
    {"id": "T0831", "name": "Manipulation of Control",            "tactic": "Impair Process Control"},
    {"id": "T0879", "name": "Damage to Property",                 "tactic": "Impact"},
    {"id": "T0815", "name": "Denial of View",                     "tactic": "Inhibit Response Function"},
    {"id": "T0888", "name": "Remote System Information Discovery", "tactic": "Discovery"},
]

ACTOR_PROFILES = {
    "Xenotime (TEMP.Veles, G0088)": {
        "T0831": 3,  # TRITON's core: reprogram SIS controller logic
        "T0879": 3,  # demonstrated destructive intent/capability
        "T0855": 2,  # unauthorized commands to Triconex controllers
        "T0836": 1,  # modified controller parameters during reprogramming
    },
    "Sandworm Team (G0034)": {
        "T0855": 3,  # CRASHOVERRIDE issued direct breaker-open commands
        "T0836": 2,  # manipulated protection relay settings
        "T0815": 2,  # operator-visibility disruption
        "T0879": 2,  # SIPROTEC-disabling component risked equipment damage
    },
    "Volt Typhoon (VOLTZITE, G1017)": {
        "T0888": 3,  # reconnaissance/discovery is core documented behavior
        # No weight on destructive techniques — not publicly reported
    },
    "ALLANITE": {
        "T0888": 2,  # reconnaissance-oriented, Dragonfly-lineage tactics
        # MITRE states no disruptive/destructive capability observed
    },
}


def score_attribution(mitre_hits: set[str]) -> tuple[dict[str, int], str | None, list[str]]:
    """
    Score actors by matched-technique weight, normalized against the strongest
    match. Returns (scores_pct, leader, tied_with). Surfaces ties explicitly
    rather than silently picking one — the model doesn't have the evidence to
    break a tie, and a real investigation would need artefacts/C2 data to do so.
    """
    raw: dict[str, int] = {}
    for actor, weights in ACTOR_PROFILES.items():
        raw[actor] = sum(w for tech, w in weights.items() if tech in mitre_hits)
    peak = max(raw.values(), default=0)
    scores = {actor: (round(val / peak * 100) if peak else 0) for actor, val in raw.items()}
    if peak == 0:
        return scores, None, []
    top = sorted([a for a, v in raw.items() if v == peak])
    leader, tied_with = top[0], top[1:]
    return scores, leader, tied_with
