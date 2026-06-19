"""Model selector with fallback chain and config-driven provider resolution."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field

from .anthropic import AnthropicProvider
from .ollama import OllamaProvider
from .openai import OpenAIProvider
from .openai_responses import OpenAIResponsesProvider
from .protocol import LLMProvider, ProviderPlugin, resolve_failover_chain
from .registry import UnknownProviderError, get_provider_spec


@dataclass
class ProviderConfig:
    """Runtime configuration for a single provider."""

    provider: str  # "anthropic" | "openai" | "ollama"
    model: str
    api_key: str = ""
    base_url: str = ""
    org_id: str = ""
    proxy: str = ""  # explicit HTTP proxy URL
    provider_routing: dict[str, str] = field(default_factory=dict)


@dataclass
class SelectorConfig:
    """Full model selection config: primary + ordered fallback chain."""

    primary: ProviderConfig
    fallbacks: list[ProviderConfig] = field(default_factory=list)


class ProviderBuildError(Exception):
    """Raised when a provider cannot be instantiated."""


def _unsupported_runtime_message(provider: str) -> str:
    return (
        f"Provider '{provider}' is registered but runtime support "
        "is not enabled in this wave"
    )


def _missing_base_url_message(provider: str) -> str:
    return f"Provider '{provider}' requires an explicit base_url"


def _build_provider(cfg: ProviderConfig) -> LLMProvider:
    """Instantiate the correct provider class from a ProviderConfig."""
    try:
        spec = get_provider_spec(cfg.provider)
    except UnknownProviderError as exc:
        raise ProviderBuildError(str(exc)) from exc

    if not spec.runtime_supported:
        raise ProviderBuildError(_unsupported_runtime_message(cfg.provider))

    base_url = cfg.base_url or spec.default_base_url

    if not base_url and spec.provider_id in {"azure", "vllm"}:
        raise ProviderBuildError(_missing_base_url_message(cfg.provider))

    match spec.backend:
        case "anthropic":
            kwargs: dict = {"api_key": cfg.api_key, "model": cfg.model}
            if base_url:
                kwargs["base_url"] = base_url
            if cfg.proxy:
                kwargs["proxy"] = cfg.proxy
            return AnthropicProvider(**kwargs)

        case "openai_compat":
            kwargs = {
                "api_key": cfg.api_key,
                "model": cfg.model,
                "provider_kind": spec.provider_kind,
            }
            if base_url:
                kwargs["base_url"] = base_url
            if cfg.org_id:
                kwargs["org_id"] = cfg.org_id
            if cfg.proxy:
                kwargs["proxy"] = cfg.proxy
            if cfg.provider_routing:
                kwargs["provider_routing"] = cfg.provider_routing
            return OpenAIProvider(**kwargs)

        case "openai_responses":
            kwargs = {
                "api_key": cfg.api_key,
                "model": cfg.model,
            }
            if base_url:
                kwargs["base_url"] = base_url
            if cfg.org_id:
                kwargs["org_id"] = cfg.org_id
            if cfg.proxy:
                kwargs["proxy"] = cfg.proxy
            return OpenAIResponsesProvider(**kwargs)

        case "ollama":
            kwargs = {"model": cfg.model}
            if base_url:
                kwargs["base_url"] = base_url
            if cfg.proxy:
                kwargs["proxy"] = cfg.proxy
            return OllamaProvider(**kwargs)

        case _:
            raise ProviderBuildError(_unsupported_runtime_message(cfg.provider))


class ModelSelector:
    """Resolves a provider from primary config with fallback chain support.

    Usage::

        selector = ModelSelector(SelectorConfig(
            primary=ProviderConfig("anthropic", "claude-sonnet-4-6", api_key="..."),
            fallbacks=[ProviderConfig("ollama", "llama3")],
        ))
        provider = selector.resolve()  # returns primary
        # on failure, call selector.next_fallback() to get next in chain
    """

    def __init__(
        self,
        config: SelectorConfig,
        plugin: ProviderPlugin | None = None,
    ) -> None:
        self._config = config
        self._chain: list[ProviderConfig] = [config.primary, *config.fallbacks]
        self._index = 0
        self._plugin = plugin

    def resolve(self) -> LLMProvider:
        """Return the current provider (primary on first call)."""
        return _build_provider(self._chain[self._index])

    @property
    def active_provider_id(self) -> str:
        """Configured provider id of the currently-active chain link.

        This is the operator-facing identity (e.g. ``"openrouter"``,
        ``"deepseek"``) — distinct from the wire-protocol backend class that
        serves it. OpenAI-compatible providers all run through
        ``OpenAIProvider``, whose ``provider_name`` is the generic ``"openai"``;
        surfacing that would mislabel an OpenRouter deployment as OpenAI.
        """
        return self._chain[self._index].provider

    def has_fallback(self) -> bool:
        """True if there is at least one more fallback available."""
        return self._index < len(self._chain) - 1

    def next_fallback(self) -> LLMProvider:
        """Advance to the next fallback and return it.

        Raises IndexError if no more fallbacks are available.
        """
        if not self.has_fallback():
            raise IndexError("No more provider fallbacks available")
        self._index += 1
        return _build_provider(self._chain[self._index])

    def next_fallback_after_failure(self, primary_failure: Exception) -> LLMProvider:
        """Advance to the next fallback, consulting ``plugin.failover_hook``.

        When a plugin is registered its ``failover_hook`` return value
        replaces the static fallback chain from ``SelectorConfig``. An
        empty chain raises ``IndexError`` exactly like ``next_fallback``.
        """
        chain = resolve_failover_chain(primary_failure, self._config, self._plugin)
        if not chain:
            raise IndexError("No fallback chain available")
        self._chain = [self._chain[0], *chain]
        self._index = 1
        return _build_provider(self._chain[self._index])

    def override_model(self, model: str) -> None:
        """Update the model on the primary provider config (for runtime switching)."""
        if model and model != self._chain[0].model:
            self._chain[0] = ProviderConfig(
                provider=self._chain[0].provider,
                model=model,
                api_key=self._chain[0].api_key,
                base_url=self._chain[0].base_url,
                org_id=self._chain[0].org_id,
                proxy=self._chain[0].proxy,
                provider_routing=self._chain[0].provider_routing,
            )

    def sync_primary(self, cfg: ProviderConfig) -> None:
        """Replace the primary provider config for future resolves and clones."""
        self._config.primary = cfg
        self._chain[0] = cfg
        self.reset()

    def override_primary_config(self, cfg: ProviderConfig) -> None:
        """Update the primary provider config in place (for per-tier routing).

        Unlike ``sync_primary`` this is a mutation rather than a wholesale
        replacement of ``_config``: the SelectorConfig and chain list stay
        intact, only ``_chain[0]`` is replaced. This is what the
        squilla_router uses to swap a different endpoint in mid-turn
        (e.g. a tier with its own ``base_url`` and ``api_key``) without
        leaking those overrides back into the global primary.
        """
        self._chain[0] = cfg

    def reset(self) -> None:
        """Reset to primary provider."""
        self._index = 0

    def clone(self) -> ModelSelector:
        """Return an independent copy for concurrent use.

        The clone starts at index 0 with its own chain list, so mutations
        (override_model, next_fallback) don't affect the original.
        """
        return ModelSelector(self._config, plugin=self._plugin)

    async def list_models(self) -> list[dict]:
        """Aggregate models from all configured providers in the chain."""
        models: list[dict] = []
        for cfg in self._chain:
            try:
                provider = _build_provider(cfg)
                provider_models = await provider.list_models()
                models.extend(m.model_dump() for m in provider_models)
            except Exception:
                continue
        return models

    @property
    def current_config(self) -> ProviderConfig:
        return self._chain[self._index]


def build_provider(
    provider: str,
    model: str,
    api_key: str = "",
    base_url: str = "",
    org_id: str = "",
) -> LLMProvider:
    """Convenience factory: build a single provider directly."""
    return _build_provider(
        ProviderConfig(
            provider=provider,
            model=model,
            api_key=api_key,
            base_url=base_url,
            org_id=org_id,
        )
    )


# ── Per-tier provider resolution (squilla_router multi-endpoint) ────────────


def resolve_tier_provider_config(
    tier_cfg: Mapping[str, Any] | dict | None,
    baseline: ProviderConfig,
) -> tuple[ProviderConfig, ProviderConfig]:
    """Resolve a per-tier ``ProviderConfig`` from router tier overrides.

    The model router can pin a tier to a different endpoint or API key by
    setting optional fields on the tier block::

        [squilla_router.tiers.c1]
        provider = "mimo"
        model = "mimo-v2.5-pro"
        base_url = "https://token-plan-cn.xiaomimimo.com/v1"
        api_key = "tp-..."   # or api_key_env = "MIMO_API_KEY"

    Anything left blank falls back to the global ``baseline`` (the
    ``[llm]`` config resolved at boot). The returned ``ProviderConfig``
    always carries the tier's own ``model`` (which is required for
    routing to mean anything), and only diverges from ``baseline`` in
    the fields the tier actually overrides.

    The function is pure: it does not read environment variables or
    touch the network. ``api_key_env`` resolution is the caller's job
    (we don't want boot-time secret loading to leak into a per-turn
    routing decision path).
    """
    if not tier_cfg:
        empty = ProviderConfig(
            provider=baseline.provider,
            model=baseline.model,
            api_key=baseline.api_key,
            base_url=baseline.base_url,
            org_id=baseline.org_id,
            proxy=baseline.proxy,
            provider_routing=dict(baseline.provider_routing or {}),
        )
        return empty, baseline

    # Accept both Mapping and a dict-like object.
    def _f(key: str, default: Any = "") -> Any:
        if isinstance(tier_cfg, Mapping):
            return tier_cfg.get(key, default)
        return getattr(tier_cfg, key, default)

    tier_model = str(_f("model", "") or "").strip()
    tier_provider = str(_f("provider", "") or "").strip()
    tier_base_url = str(_f("base_url", "") or "").strip()
    tier_api_key = _f("api_key", "")
    tier_api_key_env = str(_f("api_key_env", "") or "").strip()
    tier_org_id = str(_f("org_id", "") or "").strip()
    tier_proxy = str(_f("proxy", "") or "").strip()
    tier_routing_raw = _f("provider_routing", None)
    tier_routing = dict(tier_routing_raw) if isinstance(tier_routing_raw, Mapping) else {}

    resolved = ProviderConfig(
        provider=tier_provider or baseline.provider,
        model=tier_model or baseline.model,
        api_key=tier_api_key if tier_api_key else baseline.api_key,
        base_url=tier_base_url or baseline.base_url,
        org_id=tier_org_id or baseline.org_id,
        proxy=tier_proxy or baseline.proxy,
        provider_routing=tier_routing or dict(baseline.provider_routing or {}),
    )
    return resolved, baseline


def _resolve_tier_api_key_env(tier_cfg: Any) -> str:
    """Pull the env-var name from a tier cfg (no resolution; the caller resolves)."""
    if isinstance(tier_cfg, Mapping):
        return str(tier_cfg.get("api_key_env", "") or "").strip()
    return str(getattr(tier_cfg, "api_key_env", "") or "").strip()
