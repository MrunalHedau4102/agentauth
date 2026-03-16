"""
agentauth.agent — Secure AI agent with multi-provider LLM support.

Integrates agentauth token management, scope enforcement, prompt injection
guard, and audit logging with any LLM provider supported by agentauth.llm.

Key fix over the original:
- Each provider's tool_result messages are built in the format that
  provider actually expects (Claude vs OpenAI differ significantly).
- Claude requires:
    1. {"role":"assistant","content": <raw content blocks from API>}
    2. {"role":"user","content": [{"type":"tool_result","tool_use_id":...,"content":...}]}
  NOT the OpenAI {"role":"tool","content":"..."} format.
"""

from typing import Optional, Dict, Any, List
import json

from agentauth.llm import LLMProvider, ClaudeProvider
from agentauth.tokens import EphemeralTokenVault
from agentauth.scopes import ScopeManager, set_current_token
from agentauth.audit import AuditLogger
from agentauth.guard import PromptInjectionGuard


class SecureAgent:
    """
    AI agent with integrated agentauth security controls.

    Handles token issuance, injection guard, and audit logging automatically.
    Tool execution is the caller's responsibility — the agent passes tokens
    to tool calls and agentauth enforces scope at the execution point.

    Supports: OpenAI, Grok, Groq, Claude, Gemini, Ollama.
    Each provider's message format differences are handled internally.
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
        **llm_kwargs,
    ) -> None:
        self.llm = LLMProvider.create(
            provider_type=llm_provider,
            api_key=llm_api_key,
            model=llm_model,
            **llm_kwargs,
        )
        self.provider_type   = llm_provider.lower().strip()
        self.token_vault     = token_vault
        self.scope_manager   = scope_manager
        self.audit_logger    = audit_logger
        self.injection_guard = injection_guard or PromptInjectionGuard()
        self.max_rounds      = max_rounds

    # ── Public entry point ──────────────────────────────────────────────────

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
        Run the agent with full agentauth security enforcement.

        Returns:
            {
                "response":       str,   — final text from LLM
                "tool_calls":     list,  — every tool call made
                "rounds":         int,   — reasoning rounds used
                "blocked":        bool,  — True if agentauth blocked anything
                "block_reasons":  list,
                "token":          str,   — JWT token issued (if vault provided)
                "audit_id":       str,
            }
        """
        audit_id = None
        token    = None

        try:
            # Step 1 — Issue token
            if self.token_vault:
                token = self.token_vault.issue(
                    agent_id=agent_id,
                    scopes=scopes,
                    ttl_seconds=ttl_seconds,
                    trust_level=trust_level,
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

            # Step 3 — Agentic loop
            result = self._agent_loop(
                user_message=user_message,
                agent_id=agent_id,
                token=token,
                tools=tools,
                system_prompt=system_prompt,
                model_params=model_params or {},
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
        system_prompt: Optional[str],
        model_params: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Multi-round reasoning loop.

        CRITICAL difference from original:
        Tool result messages are built differently per provider:
          - OpenAI / Grok / Groq / Ollama: {"role":"tool","tool_call_id":...,"content":"..."}
          - Claude: assistant msg with raw blocks + user msg with tool_result blocks
          - Gemini: user msg with function_response parts
        """
        if system_prompt is None:
            system_prompt = (
                f"You are a helpful AI assistant.\n"
                f"Agent ID: {agent_id}\n"
                f"Token: {token or 'NO_TOKEN'}\n"
                "Always pass your token to every tool call."
            )

        messages: List[Dict[str, Any]] = [
            {"role": "system",  "content": system_prompt},
            {"role": "user",    "content": user_message},
        ]

        all_tool_calls:  List[Dict[str, Any]] = []
        blocked_anywhere = False
        block_reasons:   List[str] = []

        for round_num in range(self.max_rounds):

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

            # ── LLM finished ───────────────────────────────────────────────
            if stop_reason == "stop":
                return {
                    "response":      response.get("content", ""),
                    "tool_calls":    all_tool_calls,
                    "rounds":        round_num + 1,
                    "blocked":       blocked_anywhere,
                    "block_reasons": block_reasons,
                }

            # ── LLM wants to call tools ────────────────────────────────────
            if stop_reason == "tool_calls" and response.get("tool_calls"):

                tool_calls   = response["tool_calls"]
                raw_content  = response.get("raw_assistant_content")  # Claude only

                # Collect tool execution results (caller's responsibility)
                # Here we record the call and produce a placeholder result.
                # In production the caller wires in real tool execution.
                tool_results: Dict[str, str] = {}

                for tc in tool_calls:
                    fn_name = tc.get("name", "unknown")
                    try:
                        fn_args = json.loads(tc.get("arguments", "{}"))
                    except json.JSONDecodeError:
                        fn_args = {}

                    # Inject token into tool args
                    if token:
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
                            metadata={"tool": fn_name,
                                      "args": call_record["args"]},
                        )

                    # Placeholder result — real integrators replace this
                    tool_results[tc["id"]] = json.dumps({
                        "status": "executed",
                        "tool":   fn_name,
                    })

                # ── Append messages in the correct format per provider ──────
                self._append_tool_messages(
                    messages=messages,
                    tool_calls=tool_calls,
                    tool_results=tool_results,
                    raw_assistant_content=raw_content,
                    assistant_text=response.get("content", ""),
                )
                continue

            # Unexpected stop reason
            break

        return {
            "response":      "Agent reached maximum reasoning rounds.",
            "tool_calls":    all_tool_calls,
            "rounds":        self.max_rounds,
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
        """
        Append the assistant tool-call message and tool result messages
        in the format required by each provider.
        """
        if self.provider_type == "claude":
            self._append_claude_tool_messages(
                messages, raw_assistant_content, tool_results
            )
        elif self.provider_type == "gemini":
            self._append_gemini_tool_messages(
                messages, assistant_text, tool_calls, tool_results
            )
        else:
            # OpenAI / Grok / Groq / Ollama — all use the same format
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
        """
        OpenAI / Grok / Groq / Ollama format:
          1. {"role":"assistant","content":"...","tool_calls":[...]}
          2. {"role":"tool","tool_call_id":"...","content":"..."}  (one per call)
        """
        # Build tool_calls in OpenAI SDK format
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
        """
        Claude format:
          1. {"role":"assistant","content": <raw API content blocks>}
          2. {"role":"user","content": [{"type":"tool_result","tool_use_id":...,"content":"..."}]}

        raw_assistant_content must be the response.content list from the
        Anthropic API — passed through via "raw_assistant_content" in our
        normalised response dict.
        """
        if raw_assistant_content is None:
            # Fallback: should not happen if ClaudeProvider is used correctly
            return

        # Step 1 — assistant message with raw tool_use blocks
        messages.append({
            "role":    "assistant",
            "content": raw_assistant_content,
        })

        # Step 2 — user message with tool_result blocks
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
        """
        Gemini uses function_response parts (handled inside GeminiProvider.chat()
        which converts {"role":"tool",...} messages to function_response format).
        So we use OpenAI-style here and let GeminiProvider translate.
        """
        if assistant_text:
            messages.append({"role": "assistant", "content": assistant_text})

        for tc in tool_calls:
            messages.append({
                "role":         "tool",
                "tool_call_id": tc["name"],   # Gemini uses name as ID
                "content":      tool_results.get(tc["id"], "{}"),
            })


# ── Convenience factory ────────────────────────────────────────────────────

def create_agent(
    llm_provider: str,
    llm_api_key: str,
    vault: EphemeralTokenVault,
    scope_manager: ScopeManager,
    audit_logger: AuditLogger,
    **kwargs,
) -> SecureAgent:
    """
    Convenience helper to create a SecureAgent with all agentauth components.

    Args:
        llm_provider: "openai" | "grok" | "groq" | "claude" | "gemini" | "ollama"
        llm_api_key: API key
        vault: EphemeralTokenVault instance
        scope_manager: ScopeManager instance
        audit_logger: AuditLogger instance
        **kwargs: model, max_rounds, base_url (Ollama), etc.
    """
    return SecureAgent(
        llm_provider=llm_provider,
        llm_api_key=llm_api_key,
        token_vault=vault,
        scope_manager=scope_manager,
        audit_logger=audit_logger,
        **kwargs,
    )