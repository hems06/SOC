"""
CVSS 3.1 Calculator - Calculates CVSS scores for findings
"""
from app.models.finding import Severity


# CVSS 3.1 metric values
ATTACK_VECTOR = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
ATTACK_COMPLEXITY = {"L": 0.77, "H": 0.44}
PRIVILEGES_REQUIRED_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
PRIVILEGES_REQUIRED_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.50}
USER_INTERACTION = {"N": 0.85, "R": 0.62}
SCOPE = {"U": False, "C": True}
IMPACT_VALUES = {"N": 0.00, "L": 0.22, "H": 0.56}


def calculate_cvss_score(
    av: str = "N", ac: str = "L", pr: str = "N", ui: str = "N",
    s: str = "U", c: str = "N", i: str = "N", a: str = "N"
) -> dict:
    """Calculate CVSS 3.1 base score."""
    scope_changed = SCOPE.get(s, False)

    # Impact Sub-Score
    isc_base = 1 - ((1 - IMPACT_VALUES[c]) * (1 - IMPACT_VALUES[i]) * (1 - IMPACT_VALUES[a]))

    if scope_changed:
        impact = 7.52 * (isc_base - 0.029) - 3.25 * ((isc_base - 0.02) ** 15)
    else:
        impact = 6.42 * isc_base

    if impact <= 0:
        return {"score": 0.0, "vector": f"CVSS:3.1/AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:{s}/C:{c}/I:{i}/A:{a}", "details": {}}

    # Exploitability Sub-Score
    pr_values = PRIVILEGES_REQUIRED_CHANGED if scope_changed else PRIVILEGES_REQUIRED_UNCHANGED
    exploitability = 8.22 * ATTACK_VECTOR[av] * ATTACK_COMPLEXITY[ac] * pr_values[pr] * USER_INTERACTION[ui]

    if scope_changed:
        score = min(1.08 * (impact + exploitability), 10.0)
    else:
        score = min(impact + exploitability, 10.0)

    # Round up to 1 decimal
    score = round(score * 10) / 10
    if score < 0:
        score = 0.0

    vector = f"CVSS:3.1/AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:{s}/C:{c}/I:{i}/A:{a}"

    return {
        "score": score,
        "vector": vector,
        "details": {
            "attack_vector": av,
            "attack_complexity": ac,
            "privileges_required": pr,
            "user_interaction": ui,
            "scope": s,
            "confidentiality": c,
            "integrity": i,
            "availability": a,
            "impact_subscore": round(impact, 1),
            "exploitability_subscore": round(exploitability, 1),
        },
    }


def severity_to_cvss_params(severity: str, category: str = "") -> dict:
    """Map severity and category to approximate CVSS parameters."""
    defaults = {
        Severity.CRITICAL: {"av": "N", "ac": "L", "pr": "N", "ui": "N", "s": "C", "c": "H", "i": "H", "a": "H"},
        Severity.HIGH: {"av": "N", "ac": "L", "pr": "N", "ui": "N", "s": "U", "c": "H", "i": "H", "a": "N"},
        Severity.MEDIUM: {"av": "N", "ac": "L", "pr": "N", "ui": "R", "s": "U", "c": "L", "i": "L", "a": "N"},
        Severity.LOW: {"av": "N", "ac": "H", "pr": "N", "ui": "R", "s": "U", "c": "L", "i": "N", "a": "N"},
        Severity.INFORMATIONAL: {"av": "N", "ac": "H", "pr": "H", "ui": "R", "s": "U", "c": "N", "i": "N", "a": "N"},
    }

    # Category-specific adjustments
    category_overrides = {
        "authentication": {"c": "H", "i": "L"},
        "authorization": {"c": "H", "i": "H"},
        "input_validation": {"ui": "R", "i": "L"},
        "cors": {"c": "L"},
        "secrets": {"c": "H"},
        "transport_security": {"c": "L"},
    }

    params = defaults.get(severity, defaults[Severity.INFORMATIONAL]).copy()

    if category in category_overrides:
        params.update(category_overrides[category])

    return params


def calculate_cvss(finding) -> dict:
    """Calculate CVSS for a BaseFinding or Finding object."""
    params = severity_to_cvss_params(finding.severity, finding.category)
    return calculate_cvss_score(**params)
