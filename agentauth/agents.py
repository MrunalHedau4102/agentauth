"""
agentauth.agent — Secure AI agent with multi-provider LLM support.

Integrates agentauth token management, scope enforcement, prompt injection
guard, and audit logging with any LLM provider supported by agentauth.llm.

Key changes in this version:
- Accepts an optional ``AgentAuthConfig`` for all user-facing customization.
- Config values (LLM, token, agent loop) set defaults; ``run()`` kwargs
  override them per-call.
- Provider-specific tool_result message formats remain intact (Claude vs
  OpenAI differ significantly).
"""

from typing import Optional, Dict, Any, List, Tuple
import json
import uuid
from datetime import datetime, timezone
import urllib.request
import urllib.error
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from cryptography.hazmat.backends import default_backend
from sqlalchemy.orm import Session

from agentauth.llm import LLMProvider, ClaudeProvider
from agentauth.tokens import EphemeralTokenVault
from agentauth.scopes import ScopeManager, set_current_token
from agentauth.audit import AuditLogger
from agentauth.guard import PromptInjectionGuard
from agentauth.config import AgentAuthConfig, LLMConfig, TokenConfig, AgentConfig
from agentauth.db.models import AgentRegistryModel
from agentauth.exceptions import AgentNotFoundError, AgentRevokedError

import logging
logger = logging.getLogger("agentauth.agent")


# ────────────────────────────────────────────────────────────────────────────
# AgentIdentity — Cryptographic identity for AI agents
# ────────────────────────────────────────────────────────────────────────────


class AgentIdentity:
    """
    Represents a unique AI agent with cryptographic identity.
    
    Each agent has a stable agent_id (UUID), optional keypair for signing,
    trust level, and ownership information.
    """
    
    def __init__(
        self,
        agent_id: Optional[str] = None,
        display_name: Optional[str] = None,
        owner: Optional[str] = None,
        public_key: Optional[str] = None,
        private_key: Optional[str] = None,
        trust_level: str = "untrusted",
        scopes_requested: Optional[List[str]] = None,
        metadata_url: Optional[str] = None,
    ):
        """
        Initialize an AgentIdentity.
        
        Args:
            agent_id: UUID for this agent. Generated if not provided.
            display_name: Human-readable name for the agent.
            owner: Owner or team identifier.
            public_key: PEM-encoded public key for verification.
            private_key: PEM-encoded private key (kept private, not serialized).
            trust_level: One of "untrusted", "verified", or "trusted".
            scopes_requested: List of scopes requested by this agent (optional).
            metadata_url: URL where agent metadata is published (optional).
        """
        self.agent_id = agent_id or str(uuid.uuid4())
        self.display_name = display_name
        self.owner = owner
        self.public_key = public_key
        self.private_key = private_key  # Kept in memory, not persisted
        self.trust_level = trust_level
        self.scopes_requested = scopes_requested or []
        self.metadata_url = metadata_url
    
    @staticmethod
    def generate_keypair(algorithm: str = "ed25519") -> Tuple[str, str]:
        """
        Generate a cryptographic keypair.
        
        Args:
            algorithm: Key algorithm. Supported: "ed25519", "rsa".
        
        Returns:
            Tuple of (private_key_pem, public_key_pem) as strings.
        
        Raises:
            ValueError: If algorithm is not supported.
        """
        algorithm = algorithm.lower().strip()
        
        if algorithm == "ed25519":
            private_key = ed25519.Ed25519PrivateKey.generate()
            public_key = private_key.public_key()
        elif algorithm == "rsa":
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend(),
            )
            public_key = private_key.public_key()
        else:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
        
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("utf-8")
        
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")
        
        return private_pem, public_pem
    
    @staticmethod
    def from_url(url: str) -> "AgentIdentity":
        """
        Load an AgentIdentity from a remote JSON endpoint.
        
        Args:
            url: URL pointing to a JSON document with agent metadata.
        
        Returns:
            AgentIdentity instance with remote metadata loaded.
        
        Raises:
            ValueError: If the URL cannot be reached or JSON is invalid.
        
        Remote JSON format expected:
            {
                "agent_id": "optional-uuid",
                "public_key": "PEM-encoded-public-key",
                "owner": "organization-name",
                "scopes_requested": ["scope1", "scope2"],
                "display_name": "optional-display-name"
            }
        """
        try:
            with urllib.request.urlopen(url, timeout=10) as response:
                data = json.loads(response.read().decode("utf-8"))
        except (urllib.error.URLError, urllib.error.HTTPError, Exception) as e:
            raise ValueError(f"Failed to fetch agent metadata from {url}: {str(e)}")
        
        # Remote agents are always untrusted initially (regardless of what JSON says)
        agent_id = data.get("agent_id") or str(uuid.uuid4())
        
        return AgentIdentity(
            agent_id=agent_id,
            display_name=data.get("display_name"),
            owner=data.get("owner"),
            public_key=data.get("public_key"),
            trust_level="untrusted",  # Always start untrusted
            scopes_requested=data.get("scopes_requested", []),
            metadata_url=url,
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Serialize to dictionary (excludes private_key).
        
        Returns:
            Dictionary representation suitable for database storage or JSON.
        """
        return {
            "agent_id": self.agent_id,
            "display_name": self.display_name,
            "owner": self.owner,
            "public_key": self.public_key,
            "trust_level": self.trust_level,
        }


# ────────────────────────────────────────────────────────────────────────────
# AgentRegistry — Manages registered agents
# ────────────────────────────────────────────────────────────────────────────


class AgentRegistry:
    """
    Manages AI agents in the database.
    
    Handles registration, retrieval, trust level updates, and revocation.
    All operations are persisted to the AgentRegistryModel table.
    """
    
    def __init__(self, session: Session):
        """
        Initialize the registry with a database session.
        
        Args:
            session: SQLAlchemy session for database operations.
        """
        self.session = session
    
    def register_agent(self, agent: AgentIdentity) -> Dict[str, Any]:
        """
        Register a new agent in the database.
        
        Args:
            agent: AgentIdentity instance to register.
        
        Returns:
            Dictionary representation of the registered agent.
        
        Raises:
            ValueError: If agent_id is already registered.
        """
        existing = self.session.query(AgentRegistryModel).filter(
            AgentRegistryModel.agent_id == agent.agent_id
        ).first()
        
        if existing:
            raise ValueError(f"Agent {agent.agent_id} is already registered.")
        
        model = AgentRegistryModel(
            agent_id=agent.agent_id,
            display_name=agent.display_name,
            public_key=agent.public_key,
            trust_level=agent.trust_level,
            owner=agent.owner,
            is_revoked=False,
        )
        self.session.add(model)
        self.session.commit()
        
        return {
            "agent_id": model.agent_id,
            "display_name": model.display_name,
            "public_key": model.public_key,
            "trust_level": model.trust_level,
            "owner": model.owner,
            "is_revoked": model.is_revoked,
            "created_at": model.created_at.isoformat() if model.created_at else None,
        }
    
    def get_agent(self, agent_id: str) -> "AgentIdentity":
        """
        Retrieve an agent by ID as an AgentIdentity object.
        
        Args:
            agent_id: The agent's UUID.
        
        Returns:
            AgentIdentity instance.
        
        Raises:
            AgentNotFoundError: If agent is not found.
            AgentRevokedError: If agent is revoked.
        """
        model = self.session.query(AgentRegistryModel).filter(
            AgentRegistryModel.agent_id == agent_id
        ).first()
        
        if not model:
            raise AgentNotFoundError(f"Agent {agent_id} not found.")
        
        if model.is_revoked:
            raise AgentRevokedError(f"Agent {agent_id} has been revoked.")
        
        return AgentIdentity(
            agent_id=model.agent_id,
            display_name=model.display_name,
            owner=model.owner,
            public_key=model.public_key,
            trust_level=model.trust_level,
        )
    
    def list_agents(
        self,
        trust_level: Optional[str] = None,
        include_revoked: bool = False,
    ) -> List[Dict[str, Any]]:
        """
        List registered agents with optional filters.
        
        Args:
            trust_level: Filter by trust level (e.g., "verified", "trusted").
            include_revoked: Include revoked agents in results.
        
        Returns:
            List of agent dictionaries.
        """
        query = self.session.query(AgentRegistryModel)
        
        if not include_revoked:
            query = query.filter(AgentRegistryModel.is_revoked == False)
        
        if trust_level:
            query = query.filter(AgentRegistryModel.trust_level == trust_level)
        
        agents = query.all()
        return [
            {
                "agent_id": agent.agent_id,
                "display_name": agent.display_name,
                "public_key": agent.public_key,
                "trust_level": agent.trust_level,
                "owner": agent.owner,
                "is_revoked": agent.is_revoked,
                "created_at": agent.created_at.isoformat() if agent.created_at else None,
            }
            for agent in agents
        ]
    
    def trust_agent(self, agent_id: str, trust_level: str) -> Dict[str, Any]:
        """
        Update an agent's trust level.
        
        Args:
            agent_id: The agent's UUID.
            trust_level: New trust level ("untrusted", "verified", or "trusted").
        
        Returns:
            Updated agent dictionary.
        
        Raises:
            AgentNotFoundError: If agent is not found.
            ValueError: If trust_level is invalid.
        """
        if trust_level not in ("untrusted", "verified", "trusted"):
            raise ValueError(
                f"Invalid trust level: {trust_level}. "
                "Must be 'untrusted', 'verified', or 'trusted'."
            )
        
        model = self.session.query(AgentRegistryModel).filter(
            AgentRegistryModel.agent_id == agent_id
        ).first()
        
        if not model:
            raise AgentNotFoundError(f"Agent {agent_id} not found.")
        
        model.trust_level = trust_level
        model.updated_at = datetime.now(timezone.utc)
        self.session.commit()
        
        return {
            "agent_id": model.agent_id,
            "display_name": model.display_name,
            "trust_level": model.trust_level,
            "owner": model.owner,
            "is_revoked": model.is_revoked,
            "updated_at": model.updated_at.isoformat() if model.updated_at else None,
        }
    
    def revoke(self, agent_id: str) -> Dict[str, Any]:
        """
        Revoke an agent, preventing it from being retrieved or used.
        
        Args:
            agent_id: The agent's UUID.
        
        Returns:
            Updated agent dictionary.
        
        Raises:
            AgentNotFoundError: If agent is not found.
        """
        model = self.session.query(AgentRegistryModel).filter(
            AgentRegistryModel.agent_id == agent_id
        ).first()
        
        if not model:
            raise AgentNotFoundError(f"Agent {agent_id} not found.")
        
        model.is_revoked = True
        model.updated_at = datetime.now(timezone.utc)
        self.session.commit()
        
        return {
            "agent_id": model.agent_id,
            "display_name": model.display_name,
            "trust_level": model.trust_level,
            "owner": model.owner,
            "is_revoked": model.is_revoked,
            "updated_at": model.updated_at.isoformat() if model.updated_at else None,
        }
    
    def revoke_agent(self, agent_id: str) -> Dict[str, Any]:
        """
        Alias for revoke() for backward compatibility.
        
        Revoke an agent, preventing it from being retrieved or used.
        
        Args:
            agent_id: The agent's UUID.
        
        Returns:
            Updated agent dictionary.
        """
        return self.revoke(agent_id)


class SecureAgent:
    """
    AI agent with integrated agentauth security controls.

    Handles token issuance, injection guard, and audit logging automatically.
    Tool execution is the caller's responsibility — the agent passes tokens
    to tool calls and agentauth enforces scope at the execution point.

    Supports: OpenAI, Grok, Groq, Claude, Gemini, Ollama.

    Configuration
    -------------
    All default behaviour is controlled via ``AgentAuthConfig``.
    Individual ``run()`` kwargs override config defaults for that call only.

    Example::

        from agentauth.config import AgentAuthConfig, LLMConfig, TokenConfig, AgentConfig

import logging
logger = logging.getLogger("agentauth.agent")

        config = AgentAuthConfig(
            llm=LLMConfig(provider="claude", model="claude-opus-4-5", temperature=0.1),
            token=TokenConfig(ttl_seconds=120, trust_level="high"),
            agent=AgentConfig(max_rounds=5),
        )

        agent = SecureAgent(
            config=config,
            llm_api_key="sk-...",
            token_vault=vault,
            audit_logger=logger,
        )
    """

    def __init__(
        self,
        llm_api_key: str,
        config: Optional[AgentAuthConfig] = None,
        # Legacy / explicit overrides kept for backward compatibility:
        llm_provider: Optional[str] = None,
        llm_model: Optional[str] = None,
        token_vault: Optional[EphemeralTokenVault] = None,
        scope_manager: Optional[ScopeManager] = None,
        audit_logger: Optional[AuditLogger] = None,
        injection_guard: Optional[PromptInjectionGuard] = None,
        max_rounds: Optional[int] = None,
        **llm_kwargs,
    ) -> None:
        """
        Initialize SecureAgent.

        Args:
            llm_api_key: API key for the LLM provider.
            config: Central ``AgentAuthConfig`` instance. When supplied,
                    all sub-configs (LLM, token, agent) are sourced from it.
                    Explicit keyword arguments below take precedence over config
                    values where both are provided.
            llm_provider: Override the provider set in ``config.llm.provider``.
                          Accepted for backward compatibility.
            llm_model: Override the model set in ``config.llm.model``.
            token_vault: ``EphemeralTokenVault`` used to issue and verify tokens.
            scope_manager: ``ScopeManager`` for per-action scope checks.
            audit_logger: ``AuditLogger`` for tamper-evident event recording.
            injection_guard: Custom ``PromptInjectionGuard``. A default guard
                             (strict mode) is used when not supplied.
            max_rounds: Override ``config.agent.max_rounds``.
            **llm_kwargs: Extra kwargs forwarded to ``LLMProvider.create()``
                          (e.g. ``base_url`` for Ollama).
        """
        # Resolve config — fall back to defaults if caller passes nothing.
        self._config: AgentAuthConfig = config or AgentAuthConfig()

        # ── Custom provider takes priority over everything else ──────────────
        if self._config.llm.is_custom:
            self.llm = self._config.llm.custom_provider

            # Derive provider_type from the class name for message-format routing.
            # "claude" and "gemini" need special tool-result message formats;
            # everything else uses the OpenAI-compatible format.
            class_name = type(self.llm).__name__.lower()
            if "claude" in class_name:
                self.provider_type = "claude"
            elif "gemini" in class_name:
                self.provider_type = "gemini"
            else:
                self.provider_type = "openai"

        else:
            # ── Built-in provider ────────────────────────────────────────────
            # Explicit init-time kwargs beat config values.
            effective_provider = llm_provider or self._config.llm.provider
            effective_model    = llm_model    or self._config.llm.model

            # For Ollama: prefer kwarg base_url, then config, then class default.
            if "base_url" not in llm_kwargs and self._config.llm.base_url:
                llm_kwargs["base_url"] = self._config.llm.base_url

            self.llm = LLMProvider.create(
                provider_type=effective_provider,
                api_key=llm_api_key,
                model=effective_model,
                **llm_kwargs,
            )
            self.provider_type = effective_provider.lower().strip()
        self.token_vault     = token_vault
        self.scope_manager   = scope_manager
        self.audit_logger    = audit_logger
        self.injection_guard = injection_guard or PromptInjectionGuard()

        # Agent loop — explicit kwarg beats config.
        self._max_rounds: int = max_rounds if max_rounds is not None \
                                else self._config.agent.max_rounds

    # ── Public entry point ──────────────────────────────────────────────────

    def run(
        self,
        user_message: str,
        agent_id: str,
        scopes: List[str],
        tools: Optional[List[Dict[str, Any]]] = None,
        # Per-call overrides — beat config defaults when provided.
        trust_level: Optional[str] = None,
        ttl_seconds: Optional[int] = None,
        one_time_use: Optional[bool] = None,
        bound_to: Optional[str] = None,
        system_prompt: Optional[str] = None,
        model_params: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Run the agent with full agentauth security enforcement.

        Config values (set on ``AgentAuthConfig``) are used as defaults.
        Any keyword argument supplied here overrides the config for this
        call only — the config object is never mutated.

        Args:
            user_message: The user's input text.
            agent_id: UUID of the acting agent.
            scopes: List of scope strings to embed in the issued token.
            tools: Tool definitions in OpenAI function-calling schema.
            trust_level: Overrides ``config.token.trust_level`` for this call.
            ttl_seconds: Overrides ``config.token.ttl_seconds`` for this call.
            one_time_use: Overrides ``config.token.one_time_use`` for this call.
            bound_to: Overrides ``config.token.bound_to`` for this call.
            system_prompt: Overrides ``config.agent.system_prompt`` for this call.
                           Supports ``{agent_id}`` and ``{token}`` placeholders.
            model_params: Per-call model params merged on top of config defaults.

        Returns:
            Dict with keys:
            ``response``, ``tool_calls``, ``rounds``, ``blocked``,
            ``block_reasons``, ``token``, ``audit_id``.
        """
        # Resolve effective values: explicit arg > config default.
        eff_trust_level  = trust_level  if trust_level  is not None \
                           else self._config.token.trust_level
        eff_ttl          = ttl_seconds  if ttl_seconds  is not None \
                           else self._config.token.ttl_seconds
        eff_one_time_use = one_time_use if one_time_use is not None \
                           else self._config.token.one_time_use
        eff_bound_to     = bound_to     if bound_to     is not None \
                           else self._config.token.bound_to

        # Build merged model_params: llm config base + agent defaults + call overrides.
        eff_model_params = self._config.llm.build_model_params(
            overrides={
                **self._config.agent.default_model_params,
                **(model_params or {}),
            }
        )

        audit_id = None
        token    = None

        try:
            # Step 1 — Issue token
            if self.token_vault:
                token = self.token_vault.issue(
                    agent_id=agent_id,
                    scopes=scopes,
                    ttl_seconds=eff_ttl,
                    one_time_use=eff_one_time_use,
                    bound_to=eff_bound_to,
                    trust_level=eff_trust_level,
                )
                set_current_token(token)

                if self.audit_logger:
                    audit_id = self.audit_logger.log(
                        event_type="token_issued",
                        agent_id=agent_id,
                        scopes=scopes,
                    )

            # Step 2 — Injection guard on user message
            findings = self.injection_guard.inspect(
                tool_name="user_message",
                args={"content": user_message},
            )
            if findings:
                if self.audit_logger:
                    self.audit_logger.log(
                        event_type="suspicious_activity",
                        agent_id=agent_id,
                        metadata={"findings": findings},
                    )
                return {
                    "response":      "⚠️ Security: Prompt injection detected. Request blocked.",
                    "tool_calls":    [],
                    "rounds":        0,
                    "blocked":       True,
                    "block_reasons": [f["reason"] for f in findings],
                    "token":         token,
                    "audit_id":      audit_id,
                }

            # Step 3 — Resolve system prompt (per-call arg > config)
            resolved_system_prompt: Optional[str] = None
            if system_prompt is not None:
                # Caller supplied a raw string — fill placeholders inline.
                resolved_system_prompt = system_prompt.format(
                    agent_id=agent_id,
                    token=token or "NO_TOKEN",
                )
            else:
                resolved_system_prompt = self._config.agent.resolve_system_prompt(
                    agent_id=agent_id,
                    token=token,
                )

            # Step 4 — Agentic loop
            result = self._agent_loop(
                user_message=user_message,
                agent_id=agent_id,
                token=token,
                tools=tools,
                system_prompt=resolved_system_prompt,
                model_params=eff_model_params,
            )
            result["token"]    = token
            result["audit_id"] = audit_id
            return result

        except Exception as exc:
            if self.audit_logger and audit_id:
                self.audit_logger.log(
                    event_type="agent_error",
                    agent_id=agent_id,
                    outcome="failure",
                    metadata={"error": str(exc)},
                )
            return {
                "response":      f"Error: {str(exc)[:200]}",
                "tool_calls":    [],
                "rounds":        0,
                "blocked":       False,
                "block_reasons": [],
                "token":         token,
                "audit_id":      audit_id,
                "error":         str(exc),
            }

    # ── Agentic loop ────────────────────────────────────────────────────────

    def _agent_loop(
        self,
        user_message: str,
        agent_id: str,
        token: Optional[str],
        tools: Optional[List[Dict[str, Any]]],
        system_prompt: str,
        model_params: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Multi-round reasoning loop.

        Tool result messages are built differently per provider:
          - OpenAI / Grok / Groq / Ollama: {"role":"tool","tool_call_id":...,"content":"..."}
          - Claude: assistant msg with raw blocks + user msg with tool_result blocks
          - Gemini: user msg with function_response parts
        """
        messages: List[Dict[str, Any]] = [
            {"role": "system", "content": system_prompt},
            {"role": "user",   "content": user_message},
        ]

        all_tool_calls:  List[Dict[str, Any]] = []
        blocked_anywhere = False
        block_reasons:   List[str] = []

        for round_num in range(self._max_rounds):

            try:
                response = self.llm.chat(
                    messages=messages,
                    tools=tools,
                    model_params=model_params,
                )
            except Exception as exc:
                return {
                    "response":      f"LLM error: {str(exc)[:200]}",
                    "tool_calls":    all_tool_calls,
                    "rounds":        round_num + 1,
                    "blocked":       blocked_anywhere,
                    "block_reasons": block_reasons,
                }

            stop_reason = response.get("stop_reason", "stop")

            # ── Final answer ────────────────────────────────────────────────
            if stop_reason == "stop":
                return {
                    "response":      response.get("content", ""),
                    "tool_calls":    all_tool_calls,
                    "rounds":        round_num + 1,
                    "blocked":       blocked_anywhere,
                    "block_reasons": block_reasons,
                }

            # ── Tool calls ──────────────────────────────────────────────────
            if stop_reason == "tool_calls":
                tool_calls  = response.get("tool_calls", [])
                raw_content = response.get("raw_assistant_content")  # Claude only

                tool_results: Dict[str, str] = {}

                for tc in tool_calls:
                    fn_name = tc.get("name", "unknown")
                    try:
                        fn_args = json.loads(tc.get("arguments", "{}"))
                    except json.JSONDecodeError:
                        fn_args = {}

                    # Optionally inject token (controlled by config).
                    if token and self._config.agent.inject_token_into_args:
                        fn_args["token"] = token

                    call_record = {
                        "tool":    fn_name,
                        "args":    {k: v for k, v in fn_args.items() if k != "token"},
                        "blocked": False,
                    }
                    all_tool_calls.append(call_record)

                    if self.audit_logger:
                        self.audit_logger.log(
                            event_type="token_used",
                            agent_id=agent_id,
                            metadata={"tool": fn_name, "args": call_record["args"]},
                        )

                    # Placeholder result — real integrators replace this.
                    tool_results[tc["id"]] = json.dumps({
                        "status": "executed",
                        "tool":   fn_name,
                    })

                # Append messages in the correct format per provider.
                self._append_tool_messages(
                    messages=messages,
                    tool_calls=tool_calls,
                    tool_results=tool_results,
                    raw_assistant_content=raw_content,
                    assistant_text=response.get("content", ""),
                )
                continue

            # Unexpected stop reason.
            break

        return {
            "response":      "Agent reached maximum reasoning rounds.",
            "tool_calls":    all_tool_calls,
            "rounds":        self._max_rounds,
            "blocked":       blocked_anywhere,
            "block_reasons": block_reasons,
        }

    # ── Message format helpers ──────────────────────────────────────────────

    def _append_tool_messages(
        self,
        messages: List[Dict[str, Any]],
        tool_calls: List[Dict[str, Any]],
        tool_results: Dict[str, str],
        raw_assistant_content: Any,
        assistant_text: str,
    ) -> None:
        if self.provider_type == "claude":
            self._append_claude_tool_messages(
                messages, raw_assistant_content, tool_results
            )
        elif self.provider_type == "gemini":
            self._append_gemini_tool_messages(
                messages, assistant_text, tool_calls, tool_results
            )
        else:
            self._append_openai_tool_messages(
                messages, assistant_text, tool_calls, tool_results
            )

    @staticmethod
    def _append_openai_tool_messages(
        messages: List[Dict[str, Any]],
        assistant_text: str,
        tool_calls: List[Dict[str, Any]],
        tool_results: Dict[str, str],
    ) -> None:
        openai_tool_calls = [
            {
                "id":       tc["id"],
                "type":     "function",
                "function": {
                    "name":      tc["name"],
                    "arguments": tc.get("arguments", "{}"),
                },
            }
            for tc in tool_calls
        ]
        messages.append({
            "role":       "assistant",
            "content":    assistant_text or None,
            "tool_calls": openai_tool_calls,
        })
        for tc in tool_calls:
            messages.append({
                "role":         "tool",
                "tool_call_id": tc["id"],
                "content":      tool_results.get(tc["id"], "{}"),
            })

    @staticmethod
    def _append_claude_tool_messages(
        messages: List[Dict[str, Any]],
        raw_assistant_content: Any,
        tool_results: Dict[str, str],
    ) -> None:
        if raw_assistant_content is None:
            return
        messages.append({
            "role":    "assistant",
            "content": raw_assistant_content,
        })
        messages.append({
            "role": "user",
            "content": [
                {
                    "type":        "tool_result",
                    "tool_use_id": tc_id,
                    "content":     result_str,
                }
                for tc_id, result_str in tool_results.items()
            ],
        })

    @staticmethod
    def _append_gemini_tool_messages(
        messages: List[Dict[str, Any]],
        assistant_text: str,
        tool_calls: List[Dict[str, Any]],
        tool_results: Dict[str, str],
    ) -> None:
        if assistant_text:
            messages.append({"role": "assistant", "content": assistant_text})
        for tc in tool_calls:
            messages.append({
                "role":         "tool",
                "tool_call_id": tc["name"],
                "content":      tool_results.get(tc["id"], "{}"),
            })


# ── Convenience factory ────────────────────────────────────────────────────

def create_agent(
    llm_api_key: str,
    vault: EphemeralTokenVault,
    scope_manager: ScopeManager,
    audit_logger: AuditLogger,
    config: Optional[AgentAuthConfig] = None,
    **kwargs,
) -> SecureAgent:
    """
    Convenience helper to create a ``SecureAgent`` with all agentauth components.

    Args:
        llm_api_key: API key for the LLM provider.
        vault: ``EphemeralTokenVault`` instance.
        scope_manager: ``ScopeManager`` instance.
        audit_logger: ``AuditLogger`` instance.
        config: ``AgentAuthConfig`` controlling LLM, token, and agent settings.
                Defaults to ``AgentAuthConfig()`` (all library defaults) when
                not supplied.
        **kwargs: Additional overrides forwarded to ``SecureAgent.__init__``
                  (e.g. ``injection_guard``, ``max_rounds``, ``llm_provider``).
    """
    return SecureAgent(
        llm_api_key=llm_api_key,
        config=config,
        token_vault=vault,
        scope_manager=scope_manager,
        audit_logger=audit_logger,
        **kwargs,
    )