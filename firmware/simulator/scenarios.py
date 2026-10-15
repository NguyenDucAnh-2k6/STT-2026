"""Exact scenario names and honest capabilities; never route unknown names to UDP."""
from ml_engine.config.schema import LABEL_NAMES

# Implemented traffic patterns remain approximations, not benchmark reproduction.
IMPLEMENTED_SCENARIOS = frozenset({
    "Port_Scanning", "DDoS_UDP", "DDoS_TCP", "Vulnerability_scanner",
    "SQL_injection", "XSS", "Uploading", "Adversarial", "DDoS_HTTP",
})
ALIASES = {name.casefold(): name for name in LABEL_NAMES}
ALIASES.update({"xss_attack": "XSS", "adversarial": "Adversarial",
                "gan": "Adversarial", "stop": "Normal"})


def normalize_scenario(value: str) -> str:
    if not isinstance(value, str) or value.strip().casefold() not in ALIASES:
        raise ValueError("Unknown attack scenario")
    return ALIASES[value.strip().casefold()]


def require_implemented(value: str) -> str:
    scenario = normalize_scenario(value)
    if scenario != "Normal" and scenario not in IMPLEMENTED_SCENARIOS:
        raise ValueError(f"Scenario {scenario} is not implemented; no packets will be generated")
    return scenario


def require_twin_scenario(value: str) -> str:
    """Twin registry is separate from the legacy external socket generator."""
    scenario = normalize_scenario(value)
    if scenario not in LABEL_NAMES:
        raise ValueError("Unknown Twin benchmark scenario")
    return scenario
