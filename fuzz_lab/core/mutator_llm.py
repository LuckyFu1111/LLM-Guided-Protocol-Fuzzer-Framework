"""
LLMMutator — Ollama (Qwen3:8b) integration for semantic mutation.

When coverage plateaus, this module composes context-rich prompts and asks
the local LLM to generate protocol-aware fuzz seeds that target specific
logic paths (identified by CVE descriptions or RFC sections).

Provides both synchronous (requests) and asynchronous (aiohttp) APIs:
  - call_ollama() / generate_mutations()  — blocking (for simple usage)
  - call_ollama_async() / generate_mutations_async() — non-blocking (for
    concurrent operation within the orchestrator's event loop)
"""

from __future__ import annotations

import asyncio
import binascii
import logging
import re
import time
from typing import List, Optional

import requests

from fuzz_lab.config import OLLAMA_CONFIG

logger = logging.getLogger(__name__)


class LLMMutator:
    """Generate fuzz seeds via Ollama's local inference API.

    Supports both sync and async operation.  The async methods use aiohttp
    so the orchestrator can issue LLM requests without blocking the fuzzing
    loop.
    """

    def __init__(
        self,
        base_url: str = OLLAMA_CONFIG["base_url"],
        model: str = OLLAMA_CONFIG["model"],
        temperature: float = OLLAMA_CONFIG["temperature"],
        top_p: float = OLLAMA_CONFIG["top_p"],
        num_predict: int = OLLAMA_CONFIG["num_predict"],
        timeout: int = OLLAMA_CONFIG["timeout_seconds"],
        max_retries: int = OLLAMA_CONFIG["max_retries"],
        batch_size: int = OLLAMA_CONFIG["batch_size"],
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.temperature = temperature
        self.top_p = top_p
        self.num_predict = num_predict
        self.timeout = timeout
        self.max_retries = max_retries
        self.batch_size = batch_size
        self._generate_url = f"{self.base_url}/api/generate"

        # Lazy-initialised aiohttp session (created on first async call)
        self._aio_session = None

    # ------------------------------------------------------------------
    # Prompt Composition
    # ------------------------------------------------------------------

    def compose_prompt(
        self,
        seed: bytes,
        protocol: str,
        state: str = "",
        rfc_ref: str = "",
        cve_hint: str = "",
    ) -> str:
        """Build a detailed mutation prompt for the LLM.

        Parameters
        ----------
        seed : bytes
            The current fuzz seed (will be hex-encoded in the prompt).
        protocol : str
            Target protocol name (e.g. "dns", "mqtt").
        state : str
            Current protocol state (e.g. "CONNECTED", "SUBSCRIBE_SENT").
        rfc_ref : str
            RFC or spec section relevant to the target logic.
        cve_hint : str
            Optional CVE description to steer the mutation.
        """
        seed_hex = binascii.hexlify(seed).decode()
        seed_preview = seed_hex[:128] + ("..." if len(seed_hex) > 128 else "")

        parts = [
            f"You are a protocol security researcher fuzzing a {protocol.upper()} implementation.",
            f"Generate {self.batch_size} mutated protocol packets as hex strings.",
            "",
            f"Current seed (hex): {seed_preview}",
        ]

        if state:
            parts.append(f"Protocol state: {state}")
        if rfc_ref:
            parts.append(f"Relevant specification: {rfc_ref}")
        if cve_hint:
            parts.append(f"Target vulnerability pattern: {cve_hint}")

        parts.extend([
            "",
            "Requirements:",
            "1. Each mutation MUST be valid hex (0-9, a-f characters only).",
            "2. Focus on boundary conditions, integer overflows, malformed length fields,",
            "   unexpected state transitions, and edge cases in the specification.",
            "3. Vary mutation strategies: bit flips, field insertions, truncation,",
            "   type confusion, and semantic-aware changes.",
            "4. Output ONLY the hex strings, one per line, no explanations.",
            f"5. Output exactly {self.batch_size} lines.",
        ])

        return "\n".join(parts)

    # ------------------------------------------------------------------
    # Synchronous Ollama API (requests)
    # ------------------------------------------------------------------

    def call_ollama(self, prompt: str) -> List[bytes]:
        """Send prompt to Ollama and parse returned hex seeds into bytes.

        Returns a list of raw byte sequences for injection into the fuzzer.
        """
        payload = self._build_payload(prompt)
        raw_response = self._api_call_sync(payload)
        if raw_response is None:
            return []
        return self._parse_hex_seeds(raw_response)

    def generate_mutations(
        self,
        seed: bytes,
        protocol: str,
        state: str = "",
        rfc_ref: str = "",
        cve_hint: str = "",
    ) -> List[bytes]:
        """End-to-end: compose prompt, call LLM, return parsed seeds."""
        prompt = self.compose_prompt(
            seed=seed, protocol=protocol, state=state,
            rfc_ref=rfc_ref, cve_hint=cve_hint,
        )
        return self.call_ollama(prompt)

    def is_available(self) -> bool:
        """Check if the Ollama server is reachable."""
        try:
            resp = requests.get(f"{self.base_url}/api/tags", timeout=5)
            return resp.status_code == 200
        except requests.ConnectionError:
            return False

    # ------------------------------------------------------------------
    # Asynchronous Ollama API (aiohttp)
    # ------------------------------------------------------------------

    async def call_ollama_async(self, prompt: str) -> List[bytes]:
        """Async version of call_ollama using aiohttp.

        Does not block the event loop during LLM inference.
        """
        payload = self._build_payload(prompt)
        raw_response = await self._api_call_async(payload)
        if raw_response is None:
            return []
        return self._parse_hex_seeds(raw_response)

    async def generate_mutations_async(
        self,
        seed: bytes,
        protocol: str,
        state: str = "",
        rfc_ref: str = "",
        cve_hint: str = "",
    ) -> List[bytes]:
        """Async end-to-end: compose prompt, call LLM, return parsed seeds."""
        prompt = self.compose_prompt(
            seed=seed, protocol=protocol, state=state,
            rfc_ref=rfc_ref, cve_hint=cve_hint,
        )
        return await self.call_ollama_async(prompt)

    async def is_available_async(self) -> bool:
        """Async check if Ollama server is reachable."""
        session = await self._get_aio_session()
        try:
            async with session.get(
                f"{self.base_url}/api/tags",
                timeout=_aio_timeout(5),
            ) as resp:
                return resp.status == 200
        except Exception:
            return False

    async def close(self) -> None:
        """Close the aiohttp session. Call on shutdown."""
        if self._aio_session is not None and not self._aio_session.closed:
            await self._aio_session.close()
            self._aio_session = None

    # ------------------------------------------------------------------
    # Shared Helpers
    # ------------------------------------------------------------------

    def _build_payload(self, prompt: str) -> dict:
        return {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": self.temperature,
                "top_p": self.top_p,
                "num_predict": self.num_predict,
            },
        }

    # ------------------------------------------------------------------
    # Sync internals (requests)
    # ------------------------------------------------------------------

    def _api_call_sync(self, payload: dict) -> Optional[str]:
        """Make the HTTP call with retries and exponential backoff."""
        for attempt in range(1, self.max_retries + 1):
            try:
                resp = requests.post(
                    self._generate_url,
                    json=payload,
                    timeout=self.timeout,
                )
                resp.raise_for_status()
                data = resp.json()
                return data.get("response", "")
            except requests.RequestException as exc:
                wait = 2 ** attempt
                logger.warning(
                    "Ollama call attempt %d/%d failed: %s — retrying in %ds",
                    attempt, self.max_retries, exc, wait,
                )
                if attempt < self.max_retries:
                    time.sleep(wait)

        logger.error("Ollama call failed after %d attempts", self.max_retries)
        return None

    # ------------------------------------------------------------------
    # Async internals (aiohttp)
    # ------------------------------------------------------------------

    async def _get_aio_session(self):
        """Lazily create and return the aiohttp ClientSession."""
        if self._aio_session is None or self._aio_session.closed:
            import aiohttp
            self._aio_session = aiohttp.ClientSession()
        return self._aio_session

    async def _api_call_async(self, payload: dict) -> Optional[str]:
        """Async HTTP call with retries and exponential backoff."""
        session = await self._get_aio_session()

        for attempt in range(1, self.max_retries + 1):
            try:
                async with session.post(
                    self._generate_url,
                    json=payload,
                    timeout=_aio_timeout(self.timeout),
                ) as resp:
                    resp.raise_for_status()
                    data = await resp.json()
                    return data.get("response", "")
            except Exception as exc:
                wait = 2 ** attempt
                logger.warning(
                    "Async Ollama call attempt %d/%d failed: %s — retrying in %ds",
                    attempt, self.max_retries, exc, wait,
                )
                if attempt < self.max_retries:
                    await asyncio.sleep(wait)

        logger.error("Async Ollama call failed after %d attempts", self.max_retries)
        return None

    # ------------------------------------------------------------------
    # Hex Parser
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_hex_seeds(raw: str) -> List[bytes]:
        """Extract hex-encoded byte sequences from the LLM response.

        Robust against markdown formatting, explanatory text, and
        whitespace that the LLM may include despite instructions.
        """
        seeds: List[bytes] = []

        # Try line-by-line extraction first
        for line in raw.splitlines():
            line = line.strip()
            # Strip markdown code fences and bullet markers
            line = re.sub(r"^[`\-*\d.)\s]+", "", line)
            line = line.strip("`").strip()
            if not line:
                continue
            # Remove any "0x" prefix
            if line.lower().startswith("0x"):
                line = line[2:]
            # Keep only valid hex characters
            cleaned = re.sub(r"[^0-9a-fA-F]", "", line)
            if len(cleaned) >= 4:  # at least 2 bytes
                try:
                    seeds.append(binascii.unhexlify(cleaned))
                except (binascii.Error, ValueError):
                    continue

        return seeds


def _aio_timeout(seconds: int):
    """Create an aiohttp ClientTimeout from a single total-seconds value."""
    import aiohttp
    return aiohttp.ClientTimeout(total=seconds)
