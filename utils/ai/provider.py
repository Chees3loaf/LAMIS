"""Thin LLM provider interface for the ATLAS doc assistant.

Everything that talks to an external model goes through :class:`AIProvider`.
That keeps the rest of the codebase ignorant of *which* provider is in use, so
the personal-key prototype and the future company proxy differ only by config:

    * Prototype  -> base_url = None, OPENAI_API_KEY in the environment.
    * Rollout    -> base_url = "https://atlas-ai-proxy.internal/v1"; the proxy
                    holds the real key, the laptop carries no secret.

The ``openai`` import is deliberately lazy (inside the methods) so importing
this module never forces the dependency on a build that has the feature off.
"""

from __future__ import annotations

import os
from typing import List, Optional, Protocol, Sequence

import config


class AIProvider(Protocol):
    """The only two operations RAG needs from a model backend."""

    def embed(self, texts: Sequence[str]) -> List[List[float]]:
        """Return one embedding vector per input string, order-preserving."""
        ...

    def chat(self, system: str, user: str) -> str:
        """Return the model's text answer to ``user`` under ``system`` rules."""
        ...


class OpenAIProvider:
    """OpenAI-backed provider, also usable against any OpenAI-compatible proxy.

    Resolution order for the two connection settings:
        key      -> ``OPENAI_API_KEY`` env var (never stored in repo/binary).
        base_url -> ``LAMIS_AI_BASE_URL`` env var, else ``config.AI_BASE_URL``,
                    else the OpenAI default.
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        chat_model: Optional[str] = None,
        embed_model: Optional[str] = None,
    ) -> None:
        self._api_key = api_key or os.environ.get("OPENAI_API_KEY")
        self._base_url = (
            base_url
            or os.environ.get("LAMIS_AI_BASE_URL")
            or config.AI_BASE_URL
        )
        self._chat_model = chat_model or config.AI_CHAT_MODEL
        self._embed_model = embed_model or config.AI_EMBED_MODEL
        self._client = None  # lazily constructed on first use

    def _ensure_client(self):
        if self._client is not None:
            return self._client
        try:
            from openai import OpenAI  # lazy: optional dependency
        except ImportError as exc:  # pragma: no cover - depends on env
            raise RuntimeError(
                "The 'openai' package is required for the AI assistant. "
                "Install it (pip install openai) or set "
                "config.AI_ASSISTANT_ENABLED = False."
            ) from exc
        # Key resolution order: explicit arg / env var (set in __init__) ->
        # Windows Credential Manager (entered once in-app). The vault fallback
        # is what lets an installed GUI work without an env var, with the key in
        # the OS vault rather than the binary.
        if not self._api_key:
            from utils.ai import keystore
            self._api_key = keystore.get_key()
        if not self._api_key and not self._base_url:
            raise RuntimeError(
                "No OpenAI API key found. Enter one via Help -> Set OpenAI API "
                "Key (stored in Windows Credential Manager), set the "
                "OPENAI_API_KEY environment variable, or point config.AI_BASE_URL "
                "at an authenticated proxy."
            )
        # base_url=None lets the SDK use its own default endpoint.
        # max_retries: the SDK retries 429s with exponential backoff and
        # honors the Retry-After header, so a tokens-per-minute spike during
        # bulk ingest pauses and resumes instead of aborting the run. The
        # default (2) is too low for embedding a large corpus against a
        # tier-1 TPM cap; 10 comfortably rides out a full 60s window reset.
        self._client = OpenAI(
            api_key=self._api_key,
            base_url=self._base_url,
            max_retries=10,
        )
        return self._client

    def embed(self, texts: Sequence[str]) -> List[List[float]]:
        if not texts:
            return []
        client = self._ensure_client()
        resp = client.embeddings.create(model=self._embed_model, input=list(texts))
        # The API preserves input order; sort defensively on index anyway.
        ordered = sorted(resp.data, key=lambda d: d.index)
        return [d.embedding for d in ordered]

    def chat(self, system: str, user: str) -> str:
        client = self._ensure_client()
        # temperature=0 + a fixed seed makes both the HyDE draft and the answer
        # reproducible run-to-run (best-effort per OpenAI), so the same question
        # yields the same retrieval and the same answer. Seed is configurable /
        # None-able for callers that want variety.
        kwargs = dict(
            model=self._chat_model,
            temperature=0,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        )
        seed = getattr(config, "AI_SEED", None)
        if seed is not None:
            kwargs["seed"] = seed
        resp = client.chat.completions.create(**kwargs)
        return (resp.choices[0].message.content or "").strip()

    def chat_image(self, system: str, user: str, image_bytes: bytes,
                   image_format: str = "png") -> str:
        """Return the model's text answer to a prompt about an attached image.

        Used to read alarm identifiers off a pasted screenshot. ``gpt-4o-mini``
        is vision-capable, so the image is sent inline as a base64 data URI with
        ``detail='high'`` (screenshots are text-dense — high detail materially
        improves reading small alarm mnemonics). The result is only ever fed
        back into the doc-grounded pipeline; it is never shown as an answer.
        """
        import base64
        client = self._ensure_client()
        b64 = base64.b64encode(image_bytes).decode("ascii")
        data_uri = f"data:image/{image_format};base64,{b64}"
        kwargs = dict(
            model=self._chat_model,
            temperature=0,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": [
                    {"type": "text", "text": user},
                    {"type": "image_url",
                     "image_url": {"url": data_uri, "detail": "high"}},
                ]},
            ],
        )
        seed = getattr(config, "AI_SEED", None)
        if seed is not None:
            kwargs["seed"] = seed
        resp = client.chat.completions.create(**kwargs)
        return (resp.choices[0].message.content or "").strip()


def default_provider() -> AIProvider:
    """Return the provider ATLAS uses. Single seam to swap backends later."""
    return OpenAIProvider()


def check_api_key() -> str:
    """Lightweight validation of the resolved API key, for the launch-time
    check. Returns one of:
      'ok'          - key present and accepted (models.list succeeded)
      'invalid'     - key present but rejected (auth error / 401)
      'no_key'      - no key configured anywhere
      'unreachable' - couldn't verify (offline / timeout / deps missing)
    models.list() is used because it's free (no tokens) and confirms auth. We
    deliberately do NOT treat 'unreachable' as failure - a tech may be offline
    at launch, and we shouldn't disable the tool for a transient network blip.
    """
    key = os.environ.get("OPENAI_API_KEY")
    base = os.environ.get("LAMIS_AI_BASE_URL") or config.AI_BASE_URL
    if not key:
        try:
            from utils.ai import keystore
            key = keystore.get_key()
        except Exception:
            key = None
    if not key and not base:
        return "no_key"
    try:
        from openai import OpenAI
    except Exception:
        return "unreachable"
    try:
        client = OpenAI(api_key=key, base_url=base, max_retries=0, timeout=8.0)
        client.models.list()
        return "ok"
    except Exception as exc:
        status = getattr(exc, "status_code", None)
        if status in (401, 403) or "authentication" in type(exc).__name__.lower():
            return "invalid"
        return "unreachable"
