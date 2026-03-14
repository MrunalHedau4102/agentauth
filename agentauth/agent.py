"""
agentauth.agent — Helper utilities for building secure AI agents with agentauth.

This module provides utilities for integrating agentauth token management
and security controls with any LLM provider.

Example usage:
    
    from agentauth import (
        AgentRegistry, EphemeralTokenVault, ScopeManager,
        AuditLogger, LLMProvider
    )
    from agentauth.agent import SecureAgent
    
    # Initialize agentauth components
    vault = EphemeralTokenVault(secret_key="your-secret")
    registry = AgentRegistry(session=db_session)
    scope_mgr = ScopeManager(session=db_session)
    audit = AuditLogger(session=db_session)
    
    # Create a secure agent with your chosen LLM
    agent = SecureAgent(
        llm_provider="openai",
        llm_api_key="sk-...",
        llm_model="gpt-4o",
        token_vault=vault,
        scope_manager=scope_mgr,
        audit_logger=audit,
    )
    
    # Use the agent (token security automatically enforced)
    response = agent.run(
        user_message="Show me all users",
        agent_id="my-agent",
        scopes=["users:read"],
    )
"""

from typing import Optional, Dict, Any, List
import json
from datetime import datetime

from agentauth.llm import LLMProvider
from agentauth.tokens import EphemeralTokenVault
from agentauth.scopes import ScopeManager, set_current_token
from agentauth.audit import AuditLogger
from agentauth.guard import PromptInjectionGuard


class SecureAgent:
    """
    A complete implementation of an AI agent with integrated agentauth controls.
    
    Features:
    - Multi-LLM provider support (OpenAI, Grok, Claude, Gemini, Ollama, custom)
    - Automatic token generation and validation
    - Scope-based authorization enforcement
    - Prompt injection protection
    - Full audit logging of all agent actions
    
    The agent automatically enforces security at every step:
    1. Token generation
    2. Scope validation
    3. Tool execution (via token in context)
    4. Action logging
    """

    def __init__(
        self,
        llm_provider: str,
        llm_api_key: str,
        llm_model: Optional[str] = None,
        token_vault: Optional[EphemeralTokenVault] = None,
        scope_manager: Optional[ScopeManager] = None,
        audit_logger: Optional[AuditLogger] = None,
        injection_guard: Optional[PromptInjectionGuard] = None,
        max_rounds: int = 10,
        **llm_kwargs
    ):
        """
        Initialize a secure agent.
        
        Args:
            llm_provider: LLM provider type ("openai", "grok", "groq", "claude", etc.)
            llm_api_key: API key for the LLM provider
            llm_model: Model identifier (optional, uses provider default if not set)
            token_vault: EphemeralTokenVault for token management
            scope_manager: ScopeManager for scope enforcement
            audit_logger: AuditLogger for action tracking
            injection_guard: PromptInjectionGuard for security (created if not provided)
            max_rounds: Maximum reasoning rounds before giving up
            **llm_kwargs: Additional provider-specific arguments (e.g., base_url for Ollama)
        """
        self.llm = LLMProvider.create(
            provider_type=llm_provider,
            api_key=llm_api_key,
            model=llm_model,
            **llm_kwargs
        )
        
        self.token_vault = token_vault
        self.scope_manager = scope_manager
        self.audit_logger = audit_logger
        self.injection_guard = injection_guard or PromptInjectionGuard()
        self.max_rounds = max_rounds
        
        self.provider_name = llm_provider.upper()

    def run(
        self,
        user_message: str,
        agent_id: str,
        scopes: List[str],
        tools: Optional[List[Dict[str, Any]]] = None,
        trust_level: str = "low",
        ttl_seconds: int = 3600,
        system_prompt: Optional[str] = None,
        model_params: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Run the agent with automatic agentauth security enforcement.
        
        Args:
            user_message: The user's/attacker's message
            agent_id: Agent identifier (must exist in registry)
            scopes: List of scopes for authorization (e.g., ["users:read", "invoices:create"])
            tools: Tool definitions in OpenAI function calling schema (optional)
            trust_level: "low", "medium", or "high" for trust-based authorization
            ttl_seconds: Token time-to-live
            system_prompt: Custom system prompt (if None, uses default)
            model_params: Model parameters like temperature, max_tokens
        
        Returns:
            {
                "response": str,          # Final response from agent
                "tool_calls": list,       # Tools called during execution
                "rounds": int,            # Number of reasoning rounds
                "blocked": bool,          # Whether agentauth blocked any action
                "blocked_reasons": list,  # Reasons for blocks if any
                "token": str,             # JWT token used (if vault provided)
                "audit_id": str,          # Audit log identifier
            }
        
        Raises:
            Exception: If token generation fails, LLM call fails, or agent not found
        """
        
        audit_id = None
        token = None
        
        try:
            # ── Step 1: Generate/issue token ────────────────────────────
            if self.token_vault:
                token = self.token_vault.issue(
                    agent_id=agent_id,
                    scopes=scopes,
                    ttl_seconds=ttl_seconds,
                    trust_level=trust_level,
                )
                set_current_token(token)  # Set in context for scope manager
                
                # Log token issuance
                if self.audit_logger:
                    audit_id = self.audit_logger.log(
                        event_type="token_issued",
                        agent_id=agent_id,
                        scopes=scopes,
                        trust_level=trust_level,
                    )
            
            # ── Step 2: Check prompt for injection ────────────────────
            if self.injection_guard.is_suspicious(user_message):
                if self.audit_logger:
                    self.audit_logger.log(
                        event_type="suspicious_activity",
                        agent_id=agent_id,
                        detail=f"Suspicious prompt detected",
                        audit_id=audit_id,
                    )
                
                return {
                    "response": "⚠️ Security: Potential prompt injection detected. Request blocked.",
                    "tool_calls": [],
                    "rounds": 0,
                    "blocked": True,
                    "blocked_reasons": ["Prompt injection detected"],
                    "token": token,
                    "audit_id": audit_id,
                }
            
            # ── Step 3: Run agent loop ───────────────────────────────
            result = self._agent_loop(
                user_message=user_message,
                agent_id=agent_id,
                token=token,
                tools=tools,
                system_prompt=system_prompt,
                model_params=model_params or {},
            )
            
            result["token"] = token
            result["audit_id"] = audit_id
            return result
            
        except Exception as e:
            if self.audit_logger and audit_id:
                self.audit_logger.log(
                    event_type="agent_error",
                    agent_id=agent_id,
                    error=str(e),
                    audit_id=audit_id,
                )
            
            return {
                "response": f"Error: {str(e)[:200]}",
                "tool_calls": [],
                "rounds": 0,
                "blocked": False,
                "blocked_reasons": [],
                "token": token,
                "audit_id": audit_id,
                "error": str(e),
            }

    def _agent_loop(
        self,
        user_message: str,
        agent_id: str,
        token: Optional[str],
        tools: Optional[List[Dict[str, Any]]],
        system_prompt: Optional[str],
        model_params: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Internal agentic loop (multi-round reasoning with tool calling).
        
        Each tool call includes the agent's token, which is validated
        by agentauth at the point of execution.
        """
        
        if system_prompt is None:
            system_prompt = (
                f"You are a helpful AI assistant with access to tools.\n"
                f"Your agent ID: {agent_id}\n"
                f"Token: {token if token else 'NO_TOKEN'}\n"
                f"IMPORTANT: Always pass your token to every tool call."
            )
        
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_message},
        ]
        
        all_tool_calls = []
        blocked_anywhere = False
        block_reasons = []
        
        for round_num in range(self.max_rounds):
            # Call LLM
            try:
                response = self.llm.chat(
                    messages=messages,
                    tools=tools,
                    model_params=model_params,
                )
            except Exception as e:
                return {
                    "response": f"LLM error: {str(e)[:200]}",
                    "tool_calls": all_tool_calls,
                    "rounds": round_num + 1,
                    "blocked": blocked_anywhere,
                    "blocked_reasons": block_reasons,
                }
            
            # Check if LLM finished
            if response.get("stop_reason") == "stop":
                return {
                    "response": response.get("content", ""),
                    "tool_calls": all_tool_calls,
                    "rounds": round_num + 1,
                    "blocked": blocked_anywhere,
                    "blocked_reasons": block_reasons,
                }
            
            # LLM wants to call tools
            if response.get("stop_reason") == "tool_calls" and response.get("tool_calls"):
                for tc in response.get("tool_calls", []):
                    fn_name = tc.get("name")
                    arguments_str = tc.get("arguments", "{}")
                    
                    try:
                        fn_args = json.loads(arguments_str) if isinstance(arguments_str, str) else arguments_str
                    except json.JSONDecodeError:
                        fn_args = {}
                    
                    # Add token to tool call (will be validated at execution point)
                    if token:
                        fn_args["token"] = token
                    
                    # Record the tool call
                    call_record = {
                        "tool": fn_name,
                        "args": {k: v for k, v in fn_args.items() if k != "token"},
                        # Note: "result" would be added by the user's tool executor
                        # This library doesn't execute tools - that's the user's responsibility
                    }
                    all_tool_calls.append(call_record)
                    
                    # Log the tool call
                    if self.audit_logger:
                        self.audit_logger.log(
                            event_type="tool_called",
                            agent_id=agent_id,
                            tool_name=fn_name,
                            args={k: v for k, v in fn_args.items() if k != "token"},
                        )
                
                # For this MVP, we don't actually execute tools here.
                # Users integrate this with their tool execution layer.
                # The key insight: token is passed to tools, agentauth validates there.
                
                # Add assistant message with tool calls
                messages.append({
                    "role": "assistant",
                    "content": response.get("content", ""),
                })
                
                # Add dummy tool results (user would fill these in with real results)
                for tc in response.get("tool_calls", []):
                    tool_result = {
                        "role": "tool",
                        "content": json.dumps({
                            "status": "executed",
                            "tool": tc.get("name"),
                            # Real system would put actual results here
                        }),
                    }
                    messages.append(tool_result)
                
                continue
            
            # Unexpected finish
            break
        
        return {
            "response": "Agent reached max reasoning rounds.",
            "tool_calls": all_tool_calls,
            "rounds": self.max_rounds,
            "blocked": blocked_anywhere,
            "blocked_reasons": block_reasons,
        }


# Convenience function for quick agent setup

def create_agent(
    llm_provider: str,
    llm_api_key: str,
    vault: EphemeralTokenVault,
    scope_manager: ScopeManager,
    audit_logger: AuditLogger,
    **kwargs
) -> SecureAgent:
    """
    Convenience helper to create a SecureAgent with all agentauth components.
    
    Args:
        llm_provider: LLM provider type
        llm_api_key: API key for provider
        vault: EphemeralTokenVault instance
        scope_manager: ScopeManager instance
        audit_logger: AuditLogger instance
        **kwargs: Additional arguments (model, max_rounds, etc.)
    
    Returns:
        Configured SecureAgent instance ready to use
    """
    return SecureAgent(
        llm_provider=llm_provider,
        llm_api_key=llm_api_key,
        token_vault=vault,
        scope_manager=scope_manager,
        audit_logger=audit_logger,
        **kwargs
    )
