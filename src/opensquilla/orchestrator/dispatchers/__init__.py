"""AttackPathDispatcher 实现集合。

- ``SessionsSpawnDispatcher``: 拼 attack-path-v1 envelope, 调 LLMProvider
  拿 hack-deep 的完整响应, parse 漏洞 + 标 path 状态。
- ``InlineDispatcher`` (单测用): 不依赖外部 LLM, 给固定结果。

设计原则: 全部实现 ``AttackPathDispatcher`` Protocol, 可在
``RunAttackPathsOptions(dispatcher=...)`` 替换。
"""
from opensquilla.orchestrator.dispatchers.sessions_spawn import (
    SessionsSpawnDispatcher,
    SessionsSpawnDispatcherOptions,
)
from opensquilla.orchestrator.dispatchers.inline import (
    InlineDispatcher,
    InlineOutcome,
)

__all__ = [
    "SessionsSpawnDispatcher",
    "SessionsSpawnDispatcherOptions",
    "InlineDispatcher",
    "InlineOutcome",
]
