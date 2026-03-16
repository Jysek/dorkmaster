"""
Serper.dev API key pool with automatic rotation on failure.
"""

from __future__ import annotations

from hunter.utils.logging import get_logger

logger = get_logger("key_manager")


class KeyExhaustedError(Exception):
    """All API keys have been exhausted or returned errors."""


class KeyManager:
    """Manages a pool of Serper.dev API keys with auto-rotation."""

    def __init__(self, keys: list[str]) -> None:
        if not keys:
            raise ValueError(
                "At least one Serper.dev API key is required. "
                "Set SERPER_API_KEYS env var (comma-separated)."
            )
        self._keys = list(keys)
        self._index = 0
        self._dead_keys: set[str] = set()

    @property
    def current_key(self) -> str:
        if self._all_exhausted():
            raise KeyExhaustedError("All Serper.dev API keys have been exhausted.")
        return self._keys[self._index]

    def rotate(self, reason: str = "") -> str:
        dead = self._keys[self._index]
        self._dead_keys.add(dead)
        logger.warning("Key ...%s retired (%s). Rotating.", dead[-6:], reason or "unknown")

        for _ in range(len(self._keys)):
            self._index = (self._index + 1) % len(self._keys)
            if self._keys[self._index] not in self._dead_keys:
                logger.info("Switched to key ...%s", self._keys[self._index][-6:])
                return self._keys[self._index]

        raise KeyExhaustedError("All Serper.dev API keys have been exhausted.")

    def mark_success(self) -> None:
        pass

    def _all_exhausted(self) -> bool:
        return len(self._dead_keys) >= len(self._keys)

    @property
    def alive_count(self) -> int:
        return len(self._keys) - len(self._dead_keys)

    def __repr__(self) -> str:
        return (
            f"KeyManager(total={len(self._keys)}, alive={self.alive_count}, "
            f"current_idx={self._index})"
        )
