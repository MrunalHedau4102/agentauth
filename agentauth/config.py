"""
agentauth.config — Central configuration for AgentAuth.

All user-facing customization for LLM providers, token issuance,
and the SecureAgent agentic loop lives here.

Usage::

    from agentauth.config import AgentAuthConfig, LLMConfig, TokenConfig, AgentConfig

    # ── Built-in provider ────────────────────────────────────────────────────
    config = AgentAuthConfig(
        llm=LLMConfig(
            provider="claude",
            model="claude-opus-4-5",
            temperature=0.2,
            max_tokens=2048,
        ),
        token=TokenConfig(
            ttl_seconds=120,
            trust_level="medium",
            one_time_use=True,
        ),
        agent=AgentConfig(
            max_rounds=5,
            system_prompt="You are a secure assistant. Token: {token}",
            inject_token_into_args=True,
        ),
    )

    # ── Custom provider ──────────────────────────────────────────────────────
    from agentauth.llm import LLMProvider

    class MistralProvider(LLMProvider):
        def __init__(self, api_key: str, model: str):
            super().__init__(api_key, model)
            # set up your client here

        def chat(self, messages, tools=None, model_params=None):
            # call Mistral API, return normalised dict
            return {"stop_reason": "stop", "content": "...", "raw_assistant_content": None}

    config = AgentAuthConfig(
        llm=LLMConfig(
            custom_provider=MistralProvider(api_key="...", model="mistral-large"),
            temperature=0.3,
        ),
    )
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional, Dict, Any, TYPE_CHECKING

if TYPE_CHECKING:
    # Avoid circular import at runtime; only used for type hints.
    from agentauth.llm import LLMProvider as _LLMProviderType


# ---------------------------------------------------------------------------
# LLM configuration
# ---------------------------------------------------------------------------

#: Recognised built-in provider names and their default models.
_PROVIDER_DEFAULTS: Dict[str, str] = {
    "openai":  "gpt-4o",
    "grok":    "grok-beta",
    "groq":    "llama-3.3-70b-versatile",
    "claude":  "claude-opus-4-5",
    "gemini":  "gemini-2.0-flash",
    "ollama":  "llama3",
}

_VALID_PROVIDERS = frozenset(_PROVIDER_DEFAULTS.keys())


@dataclass
class LLMConfig:
    """
    Configuration for the LLM provider.

    Two usage modes
    ---------------
    **Built-in provider** — pass a ``provider`` string and optionally a
    ``model`` name. The library instantiates the provider internally::

        LLMConfig(provider="claude", model="claude-opus-4-5", temperature=0.1)

    **Custom provider** — pass a fully constructed ``LLMProvider`` instance
    via ``custom_provider``. The ``provider``, ``model``, and ``api_key``
    fields are ignored in this mode::

        LLMConfig(
            custom_provider=MyCohereProvider(api_key="...", model="command-r"),
            temperature=0.3,
            max_tokens=2048,
        )

    Attributes:
        provider: Built-in LLM backend name. One of ``"openai"``, ``"grok"``,
                  ``"groq"``, ``"claude"``, ``"gemini"``, ``"ollama"``.
                  Ignored when ``custom_provider`` is set.
        model: Model name for the built-in provider. Defaults to the
               provider's recommended model when ``None``.
               Ignored when ``custom_provider`` is set.
        api_key: API key for the built-in provider. Can also be supplied
                 to ``SecureAgent`` directly.
                 Ignored when ``custom_provider`` is set.
        base_url: Custom endpoint URL. Only used by the Ollama provider
                  (default ``"http://localhost:11434"``).
                  Ignored when ``custom_provider`` is set.
        custom_provider: A fully constructed :class:`~agentauth.llm.LLMProvider`
                         subclass instance. When supplied, all built-in provider
                         fields (``provider``, ``model``, ``api_key``,
                         ``base_url``) are ignored and this instance is used
                         directly. ``temperature``, ``max_tokens``, and
                         ``extra_model_params`` are still applied via
                         ``model_params`` on every ``chat()`` call.
        temperature: Sampling temperature passed to every ``chat()`` call.
                     ``0`` gives deterministic output. Default ``0``.
        max_tokens: Maximum tokens the model may generate per call.
                    ``None`` defers to the provider's own default.
        extra_model_params: Additional key/value pairs merged into
                            ``model_params`` on every ``chat()`` call
                            (e.g. ``{"top_p": 0.9}``).
    """

    provider: str = "openai"
    model: Optional[str] = None
    api_key: Optional[str] = None
    base_url: str = "http://localhost:11434"          # Ollama only
    custom_provider: Optional[Any] = None             # LLMProvider instance
    temperature: float = 0.0
    max_tokens: Optional[int] = None
    extra_model_params: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        # Custom provider path — skip all built-in validation.
        if self.custom_provider is not None:
            self._validate_custom_provider(self.custom_provider)
            # Remaining numeric validations still apply.
            if self.temperature < 0:
                raise ValueError("temperature must be >= 0")
            if self.max_tokens is not None and self.max_tokens < 1:
                raise ValueError("max_tokens must be >= 1")
            return

        # Built-in provider path.
        provider = self.provider.lower().strip()
        if provider not in _VALID_PROVIDERS:
            raise ValueError(
                f"Unknown LLM provider: '{self.provider}'. "
                f"Supported: {sorted(_VALID_PROVIDERS)}. "
                f"To use a custom provider, pass a LLMProvider instance "
                f"via the 'custom_provider' field instead."
            )
        self.provider = provider

        # Fill in the provider default model when the caller omits it.
        if self.model is None:
            self.model = _PROVIDER_DEFAULTS[self.provider]

        if self.temperature < 0:
            raise ValueError("temperature must be >= 0")
        if self.max_tokens is not None and self.max_tokens < 1:
            raise ValueError("max_tokens must be >= 1")

    @staticmethod
    def _validate_custom_provider(instance: Any) -> None:
        """
        Ensure the supplied object is a valid ``LLMProvider`` subclass instance.

        We do a duck-type check rather than importing ``LLMProvider`` at module
        level to avoid circular imports.

        Raises:
            TypeError: If the object is not an ``LLMProvider`` subclass or
                       does not implement ``chat()``.
        """
        # Duck-type: must have a callable chat() method.
        if not callable(getattr(instance, "chat", None)):
            raise TypeError(
                "custom_provider must be a LLMProvider subclass instance "
                "with a callable chat() method. "
                "Example:\n\n"
                "    from agentauth.llm import LLMProvider\n\n"
                "    class MyProvider(LLMProvider):\n"
                "        def chat(self, messages, tools=None, model_params=None):\n"
                "            ...\n"
                "            return {'stop_reason': 'stop', 'content': '...', "
                "'raw_assistant_content': None}\n\n"
                "    config = AgentAuthConfig(\n"
                "        llm=LLMConfig(custom_provider=MyProvider(api_key='...', model='my-model'))\n"
                "    )"
            )

    @property
    def is_custom(self) -> bool:
        """``True`` when a custom provider instance is configured."""
        return self.custom_provider is not None

    def build_model_params(
        self,
        overrides: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Build the ``model_params`` dict to pass to ``LLMProvider.chat()``.

        The merge order (lowest → highest priority):
        1. ``extra_model_params`` from this config
        2. ``temperature`` and ``max_tokens`` from this config
        3. ``overrides`` supplied at call-time

        Args:
            overrides: Per-call overrides (e.g. from ``SecureAgent.run()``).

        Returns:
            Merged ``model_params`` dict.
        """
        params: Dict[str, Any] = {**self.extra_model_params}
        params["temperature"] = self.temperature
        if self.max_tokens is not None:
            params["max_tokens"] = self.max_tokens
        if overrides:
            params.update(overrides)
        return params


# ---------------------------------------------------------------------------
# Token configuration
# ---------------------------------------------------------------------------

_VALID_TRUST_LEVELS = frozenset({"low", "medium", "high"})
_VALID_ALGORITHMS   = frozenset({"HS256"})   # extend later as needed


@dataclass
class TokenConfig:
    """
    Configuration for ephemeral token issuance.

    Attributes:
        ttl_seconds: Default time-to-live for issued tokens in seconds.
                     Can be overridden per ``SecureAgent.run()`` call.
                     Default ``30``.
        trust_level: Default trust level embedded in issued tokens.
                     One of ``"low"``, ``"medium"``, ``"high"``.
                     Can be overridden per ``SecureAgent.run()`` call.
                     Default ``"low"``.
        one_time_use: When ``True`` tokens are invalidated after first
                      verification. Requires a database session on
                      ``EphemeralTokenVault``. Default ``False``.
        bound_to: Optional IP address or agent URL to bind every issued
                  token to. ``None`` disables binding. Can be overridden
                  per ``SecureAgent.run()`` call.
        algorithm: JWT signing algorithm. Currently only ``"HS256"``
                   is supported. Default ``"HS256"``.
        secret_key: HMAC signing key. Falls back to the
                    ``AGENTAUTH_SECRET_KEY`` environment variable when
                    ``None``. Supplying it here overrides the env var.
    """

    ttl_seconds: int = 30
    trust_level: str = "low"
    one_time_use: bool = False
    bound_to: Optional[str] = None
    algorithm: str = "HS256"
    secret_key: Optional[str] = None

    def __post_init__(self) -> None:
        if self.ttl_seconds < 1:
            raise ValueError("ttl_seconds must be >= 1")

        trust = self.trust_level.lower()
        if trust not in _VALID_TRUST_LEVELS:
            raise ValueError(
                f"Invalid trust_level: '{self.trust_level}'. "
                f"Must be one of: {sorted(_VALID_TRUST_LEVELS)}"
            )
        self.trust_level = trust

        algo = self.algorithm.upper()
        if algo not in _VALID_ALGORITHMS:
            raise ValueError(
                f"Unsupported algorithm: '{self.algorithm}'. "
                f"Supported: {sorted(_VALID_ALGORITHMS)}"
            )
        self.algorithm = algo


# ---------------------------------------------------------------------------
# Agent loop configuration
# ---------------------------------------------------------------------------

@dataclass
class AgentConfig:
    """
    Configuration for the ``SecureAgent`` agentic loop.

    Attributes:
        max_rounds: Maximum LLM reasoning rounds per ``run()`` call.
                    The agent stops and returns after this many tool-call
                    cycles regardless of whether a final answer was reached.
                    Default ``10``.
        system_prompt: Static system prompt injected at the start of every
                       conversation. Supports two placeholders that are filled
                       at runtime:

                       * ``{agent_id}`` — replaced with the agent's UUID
                       * ``{token}``    — replaced with the issued JWT (or
                                          ``"NO_TOKEN"`` when no vault is set)

                       Set to ``None`` to use the built-in default prompt.
        inject_token_into_args: When ``True`` the active JWT is automatically
                                added as a ``"token"`` key to every tool-call
                                argument dict before the call is dispatched.
                                Disable if your tools retrieve the token from
                                context themselves. Default ``True``.
        default_model_params: Per-call ``model_params`` defaults applied on
                              every ``run()`` call. Merged *after*
                              ``LLMConfig.extra_model_params`` but *before*
                              explicit per-call overrides.
    """

    max_rounds: int = 10
    system_prompt: Optional[str] = None
    inject_token_into_args: bool = True
    default_model_params: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.max_rounds < 1:
            raise ValueError("max_rounds must be >= 1")

    def resolve_system_prompt(self, agent_id: str, token: Optional[str]) -> str:
        """
        Return the system prompt with ``{agent_id}`` and ``{token}``
        placeholders filled in.

        If no custom ``system_prompt`` was configured, the library's
        built-in default is used.

        Args:
            agent_id: UUID of the running agent.
            token: Issued JWT string, or ``None``.

        Returns:
            Final system prompt string ready to send to the LLM.
        """
        token_str = token or "NO_TOKEN"

        if self.system_prompt is not None:
            return self.system_prompt.format(
                agent_id=agent_id,
                token=token_str,
            )

        # Built-in default (matches original SecureAgent behaviour)
        return (
            f"You are a helpful AI assistant.\n"
            f"Agent ID: {agent_id}\n"
            f"Token: {token_str}\n"
            "Always pass your token to every tool call."
        )


# ---------------------------------------------------------------------------
# Top-level config
# ---------------------------------------------------------------------------

@dataclass
class AgentAuthConfig:
    """
    Central configuration object for the AgentAuth library.

    Pass a single instance of this class to ``SecureAgent`` to control
    all aspects of LLM selection, token issuance, and the agentic loop.

    Example::

        from agentauth.config import AgentAuthConfig, LLMConfig, TokenConfig, AgentConfig

        config = AgentAuthConfig(
            llm=LLMConfig(
                provider="claude",
                model="claude-opus-4-5",
                temperature=0.1,
                max_tokens=4096,
            ),
            token=TokenConfig(
                ttl_seconds=120,
                trust_level="high",
                one_time_use=True,
            ),
            agent=AgentConfig(
                max_rounds=8,
                system_prompt=(
                    "You are a secure assistant for agent {agent_id}. "
                    "Your token is {token}."
                ),
                inject_token_into_args=True,
            ),
        )

        agent = SecureAgent(
            config=config,
            llm_api_key="sk-...",
            token_vault=vault,
            audit_logger=logger,
        )

        result = agent.run(
            user_message="List all open orders",
            agent_id="agent-uuid",
            scopes=["orders:read"],
            # Per-call overrides (beat config defaults):
            ttl_seconds=60,
            trust_level="medium",
            model_params={"temperature": 0.5},
        )

    Attributes:
        llm:   LLM provider settings.
        token: Ephemeral token issuance settings.
        agent: Agentic loop settings.
    """

    llm:   LLMConfig   = field(default_factory=LLMConfig)
    token: TokenConfig = field(default_factory=TokenConfig)
    agent: AgentConfig = field(default_factory=AgentConfig)

    def __repr__(self) -> str:  # pragma: no cover
        return (
            f"AgentAuthConfig("
            f"llm.provider={self.llm.provider!r}, "
            f"llm.model={self.llm.model!r}, "
            f"token.ttl_seconds={self.token.ttl_seconds}, "
            f"token.trust_level={self.token.trust_level!r}, "
            f"agent.max_rounds={self.agent.max_rounds}"
            f")"
        )