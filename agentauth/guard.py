"""Prompt injection guard for AI agent tool calls."""

import base64
import re
import unicodedata
from typing import Optional, List, Dict, Any

from agentauth.exceptions import PromptInjectionSuspected


# Suspicious phrases (case-insensitive matching)
_SUSPICIOUS_PHRASES: List[str] = [
    "ignore previous instructions",
    "disregard",
    "you are now",
    "jailbreak",
    "bypass",
    "DAN",
    "act as",
    "pretend you",
    "forget your rules",
    "ignore all previous",
    "override instructions",
    "system prompt",
    "new instructions",
]

# Dangerous nested JSON keys
_DANGEROUS_KEYS: set = {
    "__proto__",
    "constructor",
    "eval",
    "exec",
    "__import__",
    "__builtins__",
    "__class__",
    "__subclasses__",
}

# Zero-width and control characters
_SUSPICIOUS_UNICODE: set = {
    "\u200b",  # zero-width space
    "\u200c",  # zero-width non-joiner
    "\u200d",  # zero-width joiner
    "\u200e",  # left-to-right mark
    "\u200f",  # right-to-left mark
    "\u202a",  # left-to-right embedding
    "\u202b",  # right-to-left embedding
    "\u202c",  # pop directional formatting
    "\u202d",  # left-to-right override
    "\u202e",  # right-to-left override
    "\u2060",  # word joiner
    "\u2061",  # function application
    "\u2062",  # invisible times
    "\u2063",  # invisible separator
    "\u2064",  # invisible plus
    "\ufeff",  # byte order mark / zero-width no-break space
}

# Regex for base64-encoded chunks (≥40 chars of base64 alphabet)
_BASE64_PATTERN = re.compile(r"[A-Za-z0-9+/=]{40,}")


class PromptInjectionGuard:
    """
    Inspects tool call arguments for prompt injection attempts
    before authorising execution.

    Detection rules:
        1. Suspicious phrases
        2. Unusual Unicode (zero-width, RTL override, etc.)
        3. Abnormally long field values (>2000 chars)
        4. Nested JSON with dangerous system keys
        5. Hidden base64-encoded strings inside normal-looking values
    """

    def __init__(
        self,
        strict: bool = True,
        audit_logger: Optional[Any] = None,
        max_field_length: int = 2000,
    ) -> None:
        """
        Initialize PromptInjectionGuard.

        Args:
            strict: If True, raises on first detection.
                    If False, collects all findings.
            audit_logger: Optional AuditLogger instance to log detections.
            max_field_length: Maximum allowed field length.
        """
        self.strict = strict
        self.audit_logger = audit_logger
        self.max_field_length = max_field_length

    def inspect(
        self,
        tool_name: str,
        args: Dict[str, Any],
    ) -> List[Dict[str, str]]:
        """
        Inspect tool call arguments for injection attempts.

        Args:
            tool_name: Name of the tool being called
            args: Argument dictionary to inspect

        Returns:
            List of finding dicts (empty if clean). Each dict
            contains ``rule``, ``field``, and ``reason`` keys.

        Raises:
            PromptInjectionSuspected: If ``strict=True`` and an
                injection is detected
        """
        findings: List[Dict[str, str]] = []

        self._walk_and_inspect(args, "", findings)

        if findings and self.audit_logger is not None:
            try:
                self.audit_logger.log(
                    event_type="suspicious_activity",
                    outcome="failure",
                    metadata={
                        "tool_name": tool_name,
                        "findings": findings,
                    },
                )
            except Exception:
                pass  # Audit logging should never block guard operation

        if findings and self.strict:
            reasons = "; ".join(f["reason"] for f in findings)
            raise PromptInjectionSuspected(
                f"Prompt injection detected in '{tool_name}': {reasons}"
            )

        return findings

    # ------------------------------------------------------------------
    # Internal inspection helpers
    # ------------------------------------------------------------------

    def _walk_and_inspect(
        self,
        obj: Any,
        path: str,
        findings: List[Dict[str, str]],
    ) -> None:
        """Recursively inspect a value."""
        if isinstance(obj, dict):
            for key, value in obj.items():
                current_path = f"{path}.{key}" if path else key

                # Rule 4: dangerous keys
                if key in _DANGEROUS_KEYS:
                    findings.append({
                        "rule": "dangerous_key",
                        "field": current_path,
                        "reason": f"Dangerous key '{key}' detected",
                    })
                    if self.strict:
                        return

                self._walk_and_inspect(value, current_path, findings)
                if self.strict and findings:
                    return

        elif isinstance(obj, list):
            for idx, item in enumerate(obj):
                current_path = f"{path}[{idx}]"
                self._walk_and_inspect(item, current_path, findings)
                if self.strict and findings:
                    return

        elif isinstance(obj, str):
            self._inspect_string(obj, path, findings)

    def _inspect_string(
        self,
        value: str,
        path: str,
        findings: List[Dict[str, str]],
    ) -> None:
        """Apply all string-level detection rules."""

        # Rule 1: Suspicious phrases
        lower_val = value.lower()
        for phrase in _SUSPICIOUS_PHRASES:
            if phrase.lower() in lower_val:
                findings.append({
                    "rule": "suspicious_phrase",
                    "field": path,
                    "reason": f"Suspicious phrase detected: '{phrase}'",
                })
                if self.strict:
                    return

        # Rule 2: Unusual Unicode
        for char in value:
            if char in _SUSPICIOUS_UNICODE:
                findings.append({
                    "rule": "unusual_unicode",
                    "field": path,
                    "reason": (
                        f"Suspicious Unicode character U+{ord(char):04X} "
                        f"detected"
                    ),
                })
                if self.strict:
                    return
                break  # One finding per field is enough

        # Rule 3: Abnormally long values
        if len(value) > self.max_field_length:
            findings.append({
                "rule": "excessive_length",
                "field": path,
                "reason": (
                    f"Field length {len(value)} exceeds maximum "
                    f"{self.max_field_length}"
                ),
            })
            if self.strict:
                return

        # Rule 5: Hidden base64 in normal-looking strings
        # Only flag if the base64 chunk decodes to something with
        # suspicious content
        for match in _BASE64_PATTERN.finditer(value):
            candidate = match.group()
            try:
                decoded = base64.b64decode(candidate).decode("utf-8", errors="ignore")
                decoded_lower = decoded.lower()
                for phrase in _SUSPICIOUS_PHRASES:
                    if phrase.lower() in decoded_lower:
                        findings.append({
                            "rule": "hidden_base64",
                            "field": path,
                            "reason": (
                                "Base64-encoded string contains suspicious "
                                f"content: '{phrase}'"
                            ),
                        })
                        if self.strict:
                            return
            except Exception:
                pass  # Not valid base64 — skip
