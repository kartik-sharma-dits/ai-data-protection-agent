from typing import Protocol


class LLMProvider(Protocol):
    """Shape a future LLM adapter (OpenAIProvider, OllamaProvider, ...) would
    implement. Not called from anywhere yet -- Phase 5 never sends text to
    an LLM. Exists now only so the eventual gateway can depend on this
    interface instead of a specific provider's SDK.
    """

    def send(self, sanitized_text: str) -> str:
        """Send already-sanitized text to the provider, return its raw response."""
        ...
