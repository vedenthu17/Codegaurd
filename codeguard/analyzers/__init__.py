"""Registry of detection layers. Each analyzer has a stable `name` used for
ablation (`Engine(disabled={...})`)."""
from __future__ import annotations


def build_all() -> list:
    from .ai_text import AiModelAnalyzer, AiTextAnalyzer
    from .bandit_layer import BanditAnalyzer
    from .deps import DependencyAnalyzer
    from .embedded import EmbeddedAnalyzer
    from .exfil import ExfilAnalyzer
    from .fences import FenceAnalyzer
    from .network import NetworkAnalyzer
    from .obfuscation import ObfuscationAnalyzer
    from .paths import PathAnalyzer
    from .resources import ResourceAnalyzer
    from .secrets import SecretsAnalyzer
    from .shell import ShellAnalyzer
    from .sql import SqlAnalyzer
    return [AiTextAnalyzer(), NetworkAnalyzer(), PathAnalyzer(), SecretsAnalyzer(), ExfilAnalyzer(),
            ObfuscationAnalyzer(), ResourceAnalyzer(), ShellAnalyzer(), EmbeddedAnalyzer(), FenceAnalyzer(), SqlAnalyzer(), DependencyAnalyzer(), BanditAnalyzer(),
            AiModelAnalyzer()]
