"""
agentauth.llm — Multi-Provider LLM Support

Provides extensible LLM provider abstraction for building agents with
agentauth token management and security controls.

Supported providers:
    - openai  → OpenAI GPT-4o, GPT-4, GPT-4-turbo
    - grok    → xAI Grok (OpenAI-compatible API)
    - groq    → Groq.com (Llama, Mixtral)
    - claude  → Anthropic Claude (native API with tool_use blocks)
    - gemini  → Google Gemini (function calling via tool_config)
    - ollama  → Local Ollama (OpenAI-compatible)

Usage:
    from agentauth.llm import LLMProvider

    llm = LLMProvider.create(
        provider_type="openai",
        api_key="sk-...",
        model="gpt-4o"
    )

    response = llm.chat(
        messages=[{"role": "user", "content": "Hello"}],
        tools=your_tools,
        model_params={"temperature": 0}
    )
    # response = {
    #     "stop_reason": "stop" | "tool_calls",
    #     "content": "...",
    #     "tool_calls": [...],       # present when stop_reason == "tool_calls"
    #     "raw_tool_blocks": [...],  # Claude only — raw tool_use blocks for
    #                                # building tool_result messages correctly
    # }
"""

from abc import ABC, abstractmethod
from typing import Optional, Dict, Any, List
import json


# ── Shared normalised response format ─────────────────────────────────────
#
# Every provider's chat() MUST return:
# {
#     "stop_reason"    : "stop" | "tool_calls",
#     "content"        : str,                   # text from LLM (may be "")
#     "tool_calls"     : [                       # only when stop_reason=="tool_calls"
#         {
#             "id"       : str,    # unique call ID
#             "name"     : str,    # tool/function name
#             "arguments": str,    # JSON string of arguments
#         }
#     ],
#     # Claude only — raw content blocks needed to build tool_result messages:
#     "raw_assistant_content": list | None,
# }
# ──────────────────────────────────────────────────────────────────────────


class LLMProvider(ABC):
    """
    Abstract base class for all LLM providers.
    All responses are normalised to the format described above.
    """

    def __init__(self, api_key: str, model: str) -> None:
        self.api_key = api_key
        self.model = model

    @abstractmethod
    def chat(
        self,
        messages: List[Dict[str, Any]],
        tools: Optional[List[Dict[str, Any]]] = None,
        model_params: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Call the LLM and return a normalised response dict.

        Args:
            messages: Conversation history.
                      OpenAI-style: [{"role": "user"|"assistant"|"system"|"tool",
                                      "content": "..."}]
                      Providers translate this internally as needed.
            tools: Tool definitions in OpenAI function calling schema:
                   [{"type":"function","function":{"name":..,"description":..,"parameters":..}}]
                   Providers translate to their native schema internally.
            model_params: Extra parameters e.g. {"temperature":0, "max_tokens":1024}

        Returns:
            Normalised response dict (see module docstring).
        """

    @staticmethod
    def create(
        provider_type: str,
        api_key: str,
        model: Optional[str] = None,
        **kwargs,
    ) -> "LLMProvider":
        """
        Factory method — returns the right provider instance.

        Args:
            provider_type: "openai" | "grok" | "groq" | "claude" | "gemini" | "ollama"
            api_key: API key for the provider
            model: Model name. Uses provider default if not given.
            **kwargs: Extra args e.g. base_url for Ollama.

        Raises:
            ValueError: Unknown provider_type.
        """
        pt = provider_type.lower().strip()

        if pt == "openai":
            return OpenAIProvider(api_key=api_key, model=model or "gpt-4o")
        elif pt == "grok":
            return GrokProvider(api_key=api_key, model=model or "grok-beta")
        elif pt == "groq":
            return GroqProvider(api_key=api_key, model=model or "llama-3.3-70b-versatile")
        elif pt == "claude":
            return ClaudeProvider(api_key=api_key, model=model or "claude-opus-4-5")
        elif pt == "gemini":
            return GeminiProvider(api_key=api_key, model=model or "gemini-2.0-flash")
        elif pt == "ollama":
            base_url = kwargs.get("base_url", "http://localhost:11434")
            return OllamaProvider(api_key=api_key, model=model or "llama3", base_url=base_url)
        else:
            raise ValueError(
                f"Unknown LLM provider: '{provider_type}'\n"
                "Supported: openai, grok, groq, claude, gemini, ollama\n"
                "To add a custom provider, subclass LLMProvider and implement chat()."
            )


# ════════════════════════════════════════════════════════════════
# SHARED HELPER
# ════════════════════════════════════════════════════════════════

def _extract_system(messages: List[Dict[str, Any]]) -> tuple[str, List[Dict[str, Any]]]:
    """
    Split system message from the rest.
    Returns (system_text, remaining_messages).
    Used by providers whose APIs take system as a separate param (Claude, Gemini).
    """
    system_parts = []
    rest = []
    for m in messages:
        if m.get("role") == "system":
            system_parts.append(m.get("content", ""))
        else:
            rest.append(m)
    return "\n".join(system_parts), rest


def _openai_tools_to_claude(tools: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Convert OpenAI function calling schema to Claude tool schema.

    OpenAI:  {"type":"function","function":{"name":..,"description":..,"parameters":{..}}}
    Claude:  {"name":..,"description":..,"input_schema":{..}}
    """
    result = []
    for t in tools:
        fn = t.get("function", t)   # handle both wrapped and unwrapped
        result.append({
            "name":         fn.get("name", ""),
            "description":  fn.get("description", ""),
            "input_schema": fn.get("parameters", {"type": "object", "properties": {}}),
        })
    return result


def _openai_tools_to_gemini(tools: List[Dict[str, Any]]) -> List[Any]:
    """
    Convert OpenAI function calling schema to Gemini FunctionDeclaration list.
    Returns a list suitable for genai.protos.Tool(function_declarations=[...]).
    """
    try:
        import google.generativeai as genai
        declarations = []
        for t in tools:
            fn = t.get("function", t)
            params = fn.get("parameters", {})
            declarations.append(
                genai.protos.FunctionDeclaration(
                    name=fn.get("name", ""),
                    description=fn.get("description", ""),
                    parameters=genai.protos.Schema(
                        type=genai.protos.Type.OBJECT,
                        properties={
                            k: genai.protos.Schema(type=genai.protos.Type.STRING)
                            for k in params.get("properties", {}).keys()
                        },
                        required=params.get("required", []),
                    ),
                )
            )
        return [genai.protos.Tool(function_declarations=declarations)]
    except Exception:
        return []


# ════════════════════════════════════════════════════════════════
# OPENAI  (gpt-4o, gpt-4, gpt-4-turbo)
# ════════════════════════════════════════════════════════════════

class OpenAIProvider(LLMProvider):
    """OpenAI GPT-4o, GPT-4, GPT-3.5-turbo."""

    def __init__(self, api_key: str, model: str) -> None:
        super().__init__(api_key, model)
        try:
            from openai import OpenAI
        except ImportError:
            raise ImportError("OpenAI provider requires: pip install openai")
        self.client = OpenAI(api_key=api_key)

    def chat(
        self,
        messages: List[Dict[str, Any]],
        tools: Optional[List[Dict[str, Any]]] = None,
        model_params: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        model_params = model_params or {}
        kwargs: Dict[str, Any] = {
            "model":       self.model,
            "messages":    messages,
            "temperature": model_params.get("temperature", 0),
        }
        if tools:
            kwargs["tools"] = tools
            kwargs["tool_choice"] = "auto"
        if "max_tokens" in model_params:
            kwargs["max_tokens"] = model_params["max_tokens"]

        response = self.client.chat.completions.create(**kwargs)
        choice = response.choices[0]

        result: Dict[str, Any] = {
            "stop_reason":           choice.finish_reason or "stop",
            "content":               choice.message.content or "",
            "raw_assistant_content": None,
        }

        if choice.finish_reason == "tool_calls" and choice.message.tool_calls:
            result["tool_calls"] = [
                {
                    "id":        tc.id,
                    "name":      tc.function.name,
                    "arguments": tc.function.arguments,
                }
                for tc in choice.message.tool_calls
            ]

        return result


# ════════════════════════════════════════════════════════════════
# GROK  (xAI — OpenAI-compatible API)
# ════════════════════════════════════════════════════════════════

class GrokProvider(LLMProvider):
    """Grok by xAI. Uses OpenAI SDK pointed at api.x.ai/v1."""

    def __init__(self, api_key: str, model: str) -> None:
        super().__init__(api_key, model)
        try:
            from openai import OpenAI
        except ImportError:
            raise ImportError("Grok provider requires: pip install openai")
        self.client = OpenAI(api_key=api_key, base_url="https://api.x.ai/v1")

    def chat(
        self,
        messages: List[Dict[str, Any]],
        tools: Optional[List[Dict[str, Any]]] = None,
        model_params: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        model_params = model_params or {}
        kwargs: Dict[str, Any] = {
            "model":       self.model,
            "messages":    messages,
            "temperature": model_params.get("temperature", 0),
        }
        if tools:
            kwargs["tools"] = tools
            kwargs["tool_choice"] = "auto"
        if "max_tokens" in model_params:
            kwargs["max_tokens"] = model_params["max_tokens"]

        response = self.client.chat.completions.create(**kwargs)
        choice = response.choices[0]
        finish = choice.finish_reason or "stop"

        result: Dict[str, Any] = {
            "stop_reason":           finish,
            "content":               choice.message.content or "",
            "raw_assistant_content": None,
        }

        if finish == "tool_calls" and choice.message.tool_calls:
            result["tool_calls"] = [
                {
                    "id":        tc.id,
                    "name":      tc.function.name,
                    "arguments": tc.function.arguments,
                }
                for tc in choice.message.tool_calls
            ]

        return result


# ════════════════════════════════════════════════════════════════
# GROQ  (Groq.com — Llama, Mixtral)
# ════════════════════════════════════════════════════════════════

class GroqProvider(LLMProvider):
    """Groq.com hosted models (Llama 3.3, Mixtral, etc.)."""

    def __init__(self, api_key: str, model: str) -> None:
        super().__init__(api_key, model)
        try:
            from groq import Groq
        except ImportError:
            raise ImportError("Groq provider requires: pip install groq")
        self.client = Groq(api_key=api_key)

    def chat(
        self,
        messages: List[Dict[str, Any]],
        tools: Optional[List[Dict[str, Any]]] = None,
        model_params: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        model_params = model_params or {}
        kwargs: Dict[str, Any] = {
            "model":       self.model,
            "messages":    messages,
            "temperature": model_params.get("temperature", 0),
        }
        if tools:
            kwargs["tools"] = tools
            kwargs["tool_choice"] = "auto"
        if "max_tokens" in model_params:
            kwargs["max_tokens"] = model_params["max_tokens"]

        response = self.client.chat.completions.create(**kwargs)
        choice = response.choices[0]
        # FIX: Groq can return None for finish_reason — guard it
        finish = choice.finish_reason or "stop"

        result: Dict[str, Any] = {
            "stop_reason":           finish,
            "content":               choice.message.content or "",
            "raw_assistant_content": None,
        }

        if finish == "tool_calls" and choice.message.tool_calls:
            result["tool_calls"] = [
                {
                    "id":        tc.id,
                    "name":      tc.function.name,
                    "arguments": tc.function.arguments,
                }
                for tc in choice.message.tool_calls
            ]

        return result


# ════════════════════════════════════════════════════════════════
# CLAUDE  (Anthropic — native API)
# ════════════════════════════════════════════════════════════════

class ClaudeProvider(LLMProvider):
    """
    Anthropic Claude.

    Key differences from OpenAI that this class handles:
    1. system prompt is a top-level param, NOT in the messages list
    2. Tool schema is {name, description, input_schema} NOT {type,function,...}
    3. Tool calls come back as content blocks of type "tool_use"
    4. Tool results must be sent as {"role":"user","content":[{"type":"tool_result",...}]}
       NOT as {"role":"tool","content":"..."}

    To support the correct tool_result format, the normalised response
    includes "raw_assistant_content" — the raw content block list that
    agent.py must pass back verbatim when building tool_result messages.
    """

    def __init__(self, api_key: str, model: str) -> None:
        super().__init__(api_key, model)
        try:
            from anthropic import Anthropic
        except ImportError:
            raise ImportError("Claude provider requires: pip install anthropic")
        self.client = Anthropic(api_key=api_key)

    def chat(
        self,
        messages: List[Dict[str, Any]],
        tools: Optional[List[Dict[str, Any]]] = None,
        model_params: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        model_params = model_params or {}

        # FIX 1: Extract system message — Claude takes it as a top-level param
        system_text, non_system_messages = _extract_system(messages)

        kwargs: Dict[str, Any] = {
            "model":      self.model,
            "messages":   non_system_messages,
            "max_tokens": model_params.get("max_tokens", 1024),
        }
        if system_text:
            kwargs["system"] = system_text
        if model_params.get("temperature") is not None:
            kwargs["temperature"] = model_params["temperature"]

        # FIX 2: Convert OpenAI tool schema → Claude tool schema
        if tools:
            kwargs["tools"] = _openai_tools_to_claude(tools)

        response = self.client.messages.create(**kwargs)

        # FIX 3: Claude returns tool calls as "tool_use" content blocks
        has_tool_use = any(
            getattr(b, "type", None) == "tool_use" for b in response.content
        )
        stop_reason = "tool_calls" if has_tool_use else "stop"

        result: Dict[str, Any] = {
            "stop_reason": stop_reason,
            "content":     next(
                (getattr(b, "text", "") for b in response.content
                 if getattr(b, "type", None) == "text"),
                ""
            ),
            # FIX 4: Pass raw content blocks so agent.py can build
            # correct tool_result messages for Claude
            "raw_assistant_content": response.content,
        }

        if has_tool_use:
            result["tool_calls"] = [
                {
                    "id":        b.id,
                    "name":      b.name,
                    "arguments": json.dumps(b.input),
                }
                for b in response.content
                if getattr(b, "type", None) == "tool_use"
            ]

        return result

    @staticmethod
    def build_tool_result_message(
        raw_assistant_content: list,
        tool_results: Dict[str, str],
    ) -> tuple[Dict[str, Any], Dict[str, Any]]:
        """
        Build the two messages Claude needs after a tool call:
          1. Assistant message with the raw tool_use content blocks
          2. User message with tool_result blocks

        Args:
            raw_assistant_content: response.content from the Claude API call
                                   (the "raw_assistant_content" field in our
                                   normalised response)
            tool_results: {tool_call_id: result_string, ...}

        Returns:
            (assistant_message, user_tool_result_message)
        """
        assistant_msg = {
            "role":    "assistant",
            "content": raw_assistant_content,
        }
        user_msg = {
            "role": "user",
            "content": [
                {
                    "type":        "tool_result",
                    "tool_use_id": tc_id,
                    "content":     result_str,
                }
                for tc_id, result_str in tool_results.items()
            ],
        }
        return assistant_msg, user_msg


# ════════════════════════════════════════════════════════════════
# GEMINI  (Google — native generativeai SDK)
# ════════════════════════════════════════════════════════════════

class GeminiProvider(LLMProvider):
    """
    Google Gemini with full function calling support.

    Fixes vs original:
    1. system_instruction is passed correctly to GenerativeModel
    2. Tool calling implemented via tool_config
    3. Function call responses normalised to standard format
    4. Tool results sent back as function_response parts
    """

    def __init__(self, api_key: str, model: str) -> None:
        super().__init__(api_key, model)
        try:
            import google.generativeai as genai
            self._genai = genai
        except ImportError:
            raise ImportError(
                "Gemini provider requires: pip install google-generativeai"
            )
        genai.configure(api_key=api_key)
        # Note: model is instantiated in chat() so system_instruction can vary
        self._api_key = api_key

    def chat(
        self,
        messages: List[Dict[str, Any]],
        tools: Optional[List[Dict[str, Any]]] = None,
        model_params: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        model_params = model_params or {}
        genai = self._genai

        # FIX 1: Extract system message and pass as system_instruction
        system_text, non_system_messages = _extract_system(messages)

        model_kwargs: Dict[str, Any] = {"model_name": self.model}
        if system_text:
            model_kwargs["system_instruction"] = system_text

        # FIX 2: Convert and attach tools
        if tools:
            gemini_tools = _openai_tools_to_gemini(tools)
            if gemini_tools:
                model_kwargs["tools"] = gemini_tools

        client = genai.GenerativeModel(**model_kwargs)

        # Convert messages to Gemini content format
        # Gemini roles: "user" | "model"
        # tool_result messages: {"role":"tool","content":...} → function_response part
        gemini_contents = []
        for m in non_system_messages:
            role = m.get("role", "user")
            content = m.get("content", "")

            if role == "tool":
                # OpenAI-style tool result → Gemini function_response
                tool_call_id = m.get("tool_call_id", "unknown")
                try:
                    result_data = json.loads(content) if isinstance(content, str) else content
                except Exception:
                    result_data = {"result": str(content)}
                gemini_contents.append({
                    "role": "user",
                    "parts": [{"function_response": {
                        "name":     tool_call_id,
                        "response": result_data,
                    }}],
                })
            elif role == "assistant":
                gemini_contents.append({
                    "role":  "model",
                    "parts": [{"text": content}] if content else [],
                })
            else:
                gemini_contents.append({
                    "role":  "user",
                    "parts": [{"text": content}],
                })

        generation_config = {
            "temperature": model_params.get("temperature", 0),
        }
        if "max_tokens" in model_params:
            generation_config["max_output_tokens"] = model_params["max_tokens"]

        response = client.generate_content(
            gemini_contents,
            generation_config=genai.types.GenerationConfig(**generation_config),
        )

        # FIX 3: Detect and normalise function calls
        candidate = response.candidates[0] if response.candidates else None
        if candidate is None:
            return {
                "stop_reason":           "stop",
                "content":               "",
                "raw_assistant_content": None,
            }

        # Check for function call parts
        function_calls = []
        text_parts = []
        for part in candidate.content.parts:
            if hasattr(part, "function_call") and part.function_call.name:
                fc = part.function_call
                function_calls.append({
                    "id":        fc.name,          # Gemini uses name as ID
                    "name":      fc.name,
                    "arguments": json.dumps(dict(fc.args)),
                })
            elif hasattr(part, "text") and part.text:
                text_parts.append(part.text)

        if function_calls:
            return {
                "stop_reason":           "tool_calls",
                "content":               " ".join(text_parts),
                "tool_calls":            function_calls,
                "raw_assistant_content": None,
            }

        return {
            "stop_reason":           "stop",
            "content":               " ".join(text_parts),
            "raw_assistant_content": None,
        }


# ════════════════════════════════════════════════════════════════
# OLLAMA  (Local models via OpenAI-compatible API)
# ════════════════════════════════════════════════════════════════

class OllamaProvider(LLMProvider):
    """
    Ollama local models (llama3, mistral, phi3, etc.).
    Uses OpenAI-compatible endpoint at http://localhost:11434.

    Note: Tool calling only works on models that support it
    (llama3, mistral-nemo, etc.). Models that don't support tools
    will return a stop response and log a warning.
    """

    # Models known to support tool calling
    TOOL_CAPABLE_MODELS = {
        "llama3", "llama3.1", "llama3.2", "llama3.3",
        "mistral", "mistral-nemo", "mixtral",
        "qwen2.5", "qwen2", "phi3",
        "command-r", "aya-expanse",
    }

    def __init__(self, api_key: str, model: str, base_url: str = "http://localhost:11434") -> None:
        super().__init__(api_key, model)
        self.base_url = base_url
        try:
            from openai import OpenAI
        except ImportError:
            raise ImportError("Ollama provider requires: pip install openai")
        # Ollama's OpenAI-compatible endpoint — api_key is ignored but required
        self.client = OpenAI(api_key="ollama", base_url=f"{base_url}/v1")

    def _model_supports_tools(self) -> bool:
        """Check if the current model likely supports tool calling."""
        model_base = self.model.split(":")[0].lower()
        return any(capable in model_base for capable in self.TOOL_CAPABLE_MODELS)

    def chat(
        self,
        messages: List[Dict[str, Any]],
        tools: Optional[List[Dict[str, Any]]] = None,
        model_params: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        model_params = model_params or {}

        kwargs: Dict[str, Any] = {
            "model":       self.model,
            "messages":    messages,
            "temperature": model_params.get("temperature", 0),
        }

        # FIX: Only pass tools if model likely supports them
        if tools:
            if self._model_supports_tools():
                kwargs["tools"] = tools
                kwargs["tool_choice"] = "auto"
            else:
                import warnings
                warnings.warn(
                    f"Ollama model '{self.model}' may not support tool calling. "
                    "Tool definitions will be omitted. "
                    "Use llama3, mistral, qwen2.5, or phi3 for tool support.",
                    UserWarning,
                    stacklevel=2,
                )

        if "max_tokens" in model_params:
            kwargs["max_tokens"] = model_params["max_tokens"]

        response = self.client.chat.completions.create(**kwargs)
        choice = response.choices[0]
        finish = choice.finish_reason or "stop"

        result: Dict[str, Any] = {
            "stop_reason":           finish,
            "content":               choice.message.content or "",
            "raw_assistant_content": None,
        }

        if finish == "tool_calls" and choice.message.tool_calls:
            result["tool_calls"] = [
                {
                    "id":        tc.id,
                    "name":      tc.function.name,
                    "arguments": tc.function.arguments,
                }
                for tc in choice.message.tool_calls
            ]

        return result


# ════════════════════════════════════════════════════════════════
# CUSTOM PROVIDER TEMPLATE
# ════════════════════════════════════════════════════════════════

"""
To add a custom provider (e.g. Cohere, Together AI, Mistral AI):

    from agentauth.llm import LLMProvider
    import json

    class CohereProvider(LLMProvider):
        def __init__(self, api_key: str, model: str):
            super().__init__(api_key, model)
            import cohere
            self.client = cohere.Client(api_key=api_key)

        def chat(self, messages, tools=None, model_params=None):
            model_params = model_params or {}
            # Transform messages to your provider's format
            # Call your provider's API
            # Return normalised dict:
            return {
                "stop_reason":           "stop",  # or "tool_calls"
                "content":               "...",
                "tool_calls":            [],       # if stop_reason=="tool_calls"
                "raw_assistant_content": None,
            }

    # Use directly:
    llm = CohereProvider(api_key="...", model="command-r")
    response = llm.chat(messages=[{"role":"user","content":"Hello"}])
"""