"""AI Red-Teaming Lab — measure prompt-injection and jailbreak robustness safely, with canary secrets.

Defensive research and education only. Test only systems you own or are explicitly authorised to test.
"""
from .attacks import ATTACKS, BENIGN_PROMPTS, Attack
from .defenses import CanaryFilter, DefendedTarget, InjectionDetector, sandwich, spotlight
from .evaluate import ConfigSummary, Trial, evaluate, judge_leak, run_trial, standard_configs, to_json, to_markdown
from .targets import DEFAULT_CANARY, FunctionTarget, ToyAssistant, build_system_prompt

__version__ = "0.1.0"

__all__ = [
    "ATTACKS", "BENIGN_PROMPTS", "Attack", "CanaryFilter", "ConfigSummary", "DEFAULT_CANARY",
    "DefendedTarget", "FunctionTarget", "InjectionDetector", "ToyAssistant", "Trial",
    "build_system_prompt", "evaluate", "judge_leak", "run_trial", "sandwich", "spotlight", "standard_configs",
    "to_json", "to_markdown",
]
