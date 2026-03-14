"""
agentauth.llm — Multi-Provider LLM Support

Provides extensible LLM provider abstraction for building agents with
agentauth token management and security controls.

Usage:
    from agentauth.llm import LLMProvider
    
    # Create a provider
    llm = LLMProvider.create(
        provider_type="openai",
        api_key="sk-...",
        model="gpt-4o"
    )
    
    # Use with agentauth tokens
    response = llm.chat(
        messages=[{"role": "user", "content": "Hello"}],
        tools=your_tools,
        model_params={"temperature": 0}
    )
"""

from abc import ABC, abstractmethod
from typing import Optional, Dict, Any, List
import json


class LLMProvider(ABC):
    """
    Abstract base class for LLM providers.
    
    Subclass this to add support for any LLM API.
    All responses are normalized to a consistent format.
    """

    def __init__(self, api_key: str, model: str):
        """
        Initialize provider with API key and model.
        
        Args:
            api_key: API key for the LLM service
            model: Model name/identifier for the provider
        """
        self.api_key = api_key
        self.model = model

    @abstractmethod
    def chat(
        self,
        messages: List[Dict[str, str]],
        tools: Optional[List[Dict[str, Any]]] = None,
        model_params: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Call the LLM with messages and optional tools.
        
        Args:
            messages: Conversation history in OpenAI format
                [{"role": "user", "content": "..."}, ...]
            tools: List of tool definitions (OpenAI function calling schema)
            model_params: Additional parameters (temperature, max_tokens, etc.)
        
        Returns:
            Standardized response dict:
            {
                "stop_reason": "stop" | "tool_calls",
                "content": str,  # text response from LLM
                "tool_calls": [  # Only if stop_reason is "tool_calls"
                    {
                        "id": str,           # unique call ID
                        "name": str,         # tool/function name
                        "arguments": str     # JSON string of arguments
                    }
                ]
            }
        
        Raises:
            Exception: If API call fails (subclass should provide details)
        """
        pass

    @staticmethod
    def create(
        provider_type: str,
        api_key: str,
        model: Optional[str] = None,
        **kwargs
    ) -> "LLMProvider":
        """
        Factory method to create the appropriate provider instance.
        
        Args:
            provider_type: "openai", "grok", "groq", "claude", "gemini", "ollama", etc.
            api_key: API key for the provider
            model: Model name (provider-specific). Uses default if not provided.
            **kwargs: Additional provider-specific arguments
        
        Returns:
            Initialized LLMProvider subclass instance
        
        Raises:
            ValueError: If provider_type is unknown
        """
        provider_type = provider_type.lower().strip()

        if provider_type == "openai":
            return OpenAIProvider(api_key=api_key, model=model or "gpt-4o")

        elif provider_type == "grok":
            return GrokProvider(api_key=api_key, model=model or "grok-beta")

        elif provider_type == "groq":
            return GroqProvider(api_key=api_key, model=model or "llama-3.3-70b-versatile")

        elif provider_type == "claude":
            return ClaudeProvider(api_key=api_key, model=model or "claude-3-5-sonnet-20241022")

        elif provider_type == "gemini":
            return GeminiProvider(api_key=api_key, model=model or "gemini-2.0-flash")

        elif provider_type == "ollama":
            base_url = kwargs.get("base_url", "http://localhost:11434")
            return OllamaProvider(api_key=api_key, model=model or "llama2", base_url=base_url)

        else:
            raise ValueError(
                f"Unknown LLM provider: '{provider_type}'\n"
                f"Supported built-in providers:\n"
                f"  - openai (OpenAI GPT-4o)\n"
                f"  - grok (xAI Grok)\n"
                f"  - groq (Groq.com)\n"
                f"  - claude (Anthropic Claude)\n"
                f"  - gemini (Google Gemini)\n"
                f"  - ollama (Local Ollama)\n"
                f"To add a custom provider, subclass LLMProvider and implement chat()."
            )


# ════════════════════════════════════════════════════════════════════════════
# OPENAI IMPLEMENTATION
# ════════════════════════════════════════════════════════════════════════════


class OpenAIProvider(LLMProvider):
    """OpenAI GPT-4o, GPT-4, GPT-3.5-turbo via standard OpenAI API."""

    def __init__(self, api_key: str, model: str):
        super().__init__(api_key, model)
        try:
            from openai import OpenAI
        except ImportError:
            raise ImportError(
                "OpenAI provider requires: pip install openai"
            )
        self.client = OpenAI(api_key=api_key)

    def chat(
        self,
        messages: List[Dict[str, str]],
        tools: Optional[List[Dict[str, Any]]] = None,
        model_params: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Call OpenAI chat completion API."""
        model_params = model_params or {}

        kwargs = {
            "model": self.model,
            "messages": messages,
            "temperature": model_params.get("temperature", 0),
        }

        if tools:
            kwargs["tools"] = tools
            kwargs["tool_choice"] = "auto"

        if "max_tokens" in model_params:
            kwargs["max_tokens"] = model_params["max_tokens"]

        response = self.client.chat.completions.create(**kwargs)

        choice = response.choices[0]
        result = {
            "stop_reason": choice.finish_reason or "stop",
            "content": choice.message.content or "",
        }

        if choice.finish_reason == "tool_calls" and choice.message.tool_calls:
            result["tool_calls"] = [
                {
                    "id": tc.id,
                    "name": tc.function.name,
                    "arguments": tc.function.arguments,
                }
                for tc in choice.message.tool_calls
            ]

        return result


# ════════════════════════════════════════════════════════════════════════════
# GROK IMPLEMENTATION (xAI)
# ════════════════════════════════════════════════════════════════════════════


class GrokProvider(LLMProvider):
    """Grok by xAI (OpenAI-compatible API at api.x.ai/v1)."""

    def __init__(self, api_key: str, model: str):
        super().__init__(api_key, model)
        try:
            from openai import OpenAI
        except ImportError:
            raise ImportError(
                "Grok provider requires: pip install openai"
            )
        self.client = OpenAI(
            api_key=api_key,
            base_url="https://api.x.ai/v1",
        )

    def chat(
        self,
        messages: List[Dict[str, str]],
        tools: Optional[List[Dict[str, Any]]] = None,
        model_params: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Call Grok API (OpenAI-compatible)."""
        model_params = model_params or {}

        kwargs = {
            "model": self.model,
            "messages": messages,
            "temperature": model_params.get("temperature", 0),
        }

        if tools:
            kwargs["tools"] = tools
            kwargs["tool_choice"] = "auto"

        if "max_tokens" in model_params:
            kwargs["max_tokens"] = model_params["max_tokens"]

        response = self.client.chat.completions.create(**kwargs)

        choice = response.choices[0]
        result = {
            "stop_reason": choice.finish_reason or "stop",
            "content": choice.message.content or "",
        }

        if choice.finish_reason == "tool_calls" and choice.message.tool_calls:
            result["tool_calls"] = [
                {
                    "id": tc.id,
                    "name": tc.function.name,
                    "arguments": tc.function.arguments,
                }
                for tc in choice.message.tool_calls
            ]

        return result


# ════════════════════════════════════════════════════════════════════════════
# GROQ IMPLEMENTATION (Groq.com)
# ════════════════════════════════════════════════════════════════════════════


class GroqProvider(LLMProvider):
    """Groq.com (fully-managed fine-tuned models: Llama, Mixtral, etc.)."""

    def __init__(self, api_key: str, model: str):
        super().__init__(api_key, model)
        try:
            from groq import Groq
        except ImportError:
            raise ImportError(
                "Groq provider requires: pip install groq"
            )
        self.client = Groq(api_key=api_key)

    def chat(
        self,
        messages: List[Dict[str, str]],
        tools: Optional[List[Dict[str, Any]]] = None,
        model_params: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Call Groq API."""
        model_params = model_params or {}

        kwargs = {
            "model": self.model,
            "messages": messages,
            "temperature": model_params.get("temperature", 0),
        }

        if tools:
            kwargs["tools"] = tools
            kwargs["tool_choice"] = "auto"

        if "max_tokens" in model_params:
            kwargs["max_tokens"] = model_params["max_tokens"]

        response = self.client.chat.completions.create(**kwargs)

        choice = response.choices[0]
        result = {
            "stop_reason": choice.finish_reason or "stop",
            "content": choice.message.content or "",
        }

        if choice.finish_reason == "tool_calls" and choice.message.tool_calls:
            result["tool_calls"] = [
                {
                    "id": tc.id,
                    "name": tc.function.name,
                    "arguments": tc.function.arguments,
                }
                for tc in choice.message.tool_calls
            ]

        return result


# ════════════════════════════════════════════════════════════════════════════
# CLAUDE IMPLEMENTATION (Anthropic)
# ════════════════════════════════════════════════════════════════════════════


class ClaudeProvider(LLMProvider):
    """Claude by Anthropic (best reasoning)."""

    def __init__(self, api_key: str, model: str):
        super().__init__(api_key, model)
        try:
            from anthropic import Anthropic
        except ImportError:
            raise ImportError(
                "Claude provider requires: pip install anthropic"
            )
        self.client = Anthropic(api_key=api_key)

    def chat(
        self,
        messages: List[Dict[str, str]],
        tools: Optional[List[Dict[str, Any]]] = None,
        model_params: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Call Claude API."""
        model_params = model_params or {}

        kwargs = {
            "model": self.model,
            "messages": messages,
            "max_tokens": model_params.get("max_tokens", 1024),
            "temperature": model_params.get("temperature", 0),
        }

        if tools:
            kwargs["tools"] = tools

        response = self.client.messages.create(**kwargs)

        # Claude uses "tool_use" blocks for tool calls
        stop_reason = (
            "tool_calls" if any(b.type == "tool_use" for b in response.content)
            else "stop"
        )

        result = {
            "stop_reason": stop_reason,
            "content": next(
                (b.text for b in response.content if hasattr(b, "text")),
                ""
            ),
        }

        if stop_reason == "tool_calls":
            result["tool_calls"] = [
                {
                    "id": b.id,
                    "name": b.name,
                    "arguments": json.dumps(b.input),
                }
                for b in response.content if b.type == "tool_use"
            ]

        return result


# ════════════════════════════════════════════════════════════════════════════
# GEMINI IMPLEMENTATION (Google)
# ════════════════════════════════════════════════════════════════════════════


class GeminiProvider(LLMProvider):
    """Gemini by Google (fast, free tier available)."""

    def __init__(self, api_key: str, model: str):
        super().__init__(api_key, model)
        try:
            import google.generativeai as genai
        except ImportError:
            raise ImportError(
                "Gemini provider requires: pip install google-generativeai"
            )
        genai.configure(api_key=api_key)
        self.client = genai.GenerativeModel(model)

    def chat(
        self,
        messages: List[Dict[str, str]],
        tools: Optional[List[Dict[str, Any]]] = None,
        model_params: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Call Gemini API."""
        model_params = model_params or {}

        # Convert OpenAI-style messages to Gemini format
        gemini_messages = [
            {
                "role": "user" if m["role"] == "user" else "model",
                "parts": [{"text": m["content"]}]
            }
            for m in messages
        ]

        kwargs = {"contents": gemini_messages}

        if model_params:
            kwargs["generation_config"] = {
                "temperature": model_params.get("temperature", 0),
            }
            if "max_tokens" in model_params:
                kwargs["generation_config"]["max_output_tokens"] = model_params["max_tokens"]

        response = self.client.generate_content(**kwargs)

        result = {
            "stop_reason": "stop",
            "content": response.text or "",
        }

        return result


# ════════════════════════════════════════════════════════════════════════════
# OLLAMA IMPLEMENTATION (Local models)
# ════════════════════════════════════════════════════════════════════════════


class OllamaProvider(LLMProvider):
    """Ollama (local LLMs: llama2, mistral, neural-chat, etc.)."""

    def __init__(self, api_key: str, model: str, base_url: str = "http://localhost:11434"):
        super().__init__(api_key, model)
        try:
            from openai import OpenAI
        except ImportError:
            raise ImportError(
                "Ollama provider requires: pip install openai"
            )
        # Ollama uses OpenAI-compatible API
        self.client = OpenAI(
            api_key="ollama",  # Dummy key, not used by Ollama
            base_url=base_url,
        )

    def chat(
        self,
        messages: List[Dict[str, str]],
        tools: Optional[List[Dict[str, Any]]] = None,
        model_params: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Call Ollama API (OpenAI-compatible)."""
        model_params = model_params or {}

        kwargs = {
            "model": self.model,
            "messages": messages,
            "temperature": model_params.get("temperature", 0),
        }

        if tools:
            kwargs["tools"] = tools
            kwargs["tool_choice"] = "auto"

        if "max_tokens" in model_params:
            kwargs["max_tokens"] = model_params["max_tokens"]

        response = self.client.chat.completions.create(**kwargs)

        choice = response.choices[0]
        result = {
            "stop_reason": choice.finish_reason or "stop",
            "content": choice.message.content or "",
        }

        if choice.finish_reason == "tool_calls" and choice.message.tool_calls:
            result["tool_calls"] = [
                {
                    "id": tc.id,
                    "name": tc.function.name,
                    "arguments": tc.function.arguments,
                }
                for tc in choice.message.tool_calls
            ]

        return result


# ════════════════════════════════════════════════════════════════════════════
# TEMPLATE FOR CUSTOM PROVIDERS
# ════════════════════════════════════════════════════════════════════════════

"""
CUSTOM PROVIDER EXAMPLE:

If you want to add support for a new LLM (e.g., Cohere, Together AI, etc.),
create a provider subclass:

    from agentauth.llm import LLMProvider
    
    class CohereProvider(LLMProvider):
        '''Cohere API support.'''
        
        def __init__(self, api_key: str, model: str):
            super().__init__(api_key, model)
            import cohere
            self.client = cohere.Client(api_key=api_key)
        
        def chat(self, messages, tools=None, model_params=None):
            '''Call Cohere API and return standardized response.'''
            model_params = model_params or {}
            
            # Transform messages to Cohere format
            # Call self.client.chat(...)
            # Return {"stop_reason": ..., "content": ..., "tool_calls": ...}
            response = self.client.chat(
                model=self.model,
                messages=messages,
                temperature=model_params.get("temperature", 0),
            )
            
            return {
                "stop_reason": "stop",
                "content": response.text,
            }

Then use it:
    
    from my_providers import CohereProvider
    
    # Direct instantiation
    llm = CohereProvider(api_key="...", model="command-r")
    
    # Or register with factory
    # (Would need to modify LLMProvider.create() or create a registry)
"""
