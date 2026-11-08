from __future__ import annotations

from typing import Any

from agent_warrant.ledger import LedgerUnavailable

from executor.targets import EffectCall, Target


class CapturingTarget:
    """Sits between the executor and a target and keeps every call, as a network observer or a leaked log would.
    `inner` is the real target, reachable by an attacker who has the captured material."""

    def __init__(self, inner: Target) -> None:
        self.inner = inner
        self.tools = inner.tools
        self.calls: list[EffectCall] = []

    def perform(self, call: EffectCall) -> dict[str, Any]:
        self.calls.append(call)
        return self.inner.perform(call)


class CrashingMinter:
    """Mints like `inner`, except that the first `crashes` attempts raise after the issuance record was written."""

    def __init__(self, inner: Any, crashes: int) -> None:
        self._inner = inner
        self.remaining = crashes
        self.attempts = 0

    def mint(self, *arguments: Any) -> Any:
        self.attempts += 1
        if self.remaining:
            self.remaining -= 1
            raise RuntimeError("simulated crash while minting")
        return self._inner.mint(*arguments)


class FlakyLedger:
    """Delegates to a ledger, except that the first call to `method` raises LedgerUnavailable, as a crash between
    two ledger steps would."""

    def __init__(self, inner: Any, method: str) -> None:
        self._inner = inner
        self._method = method
        self.failed = False

    def __getattr__(self, name: str) -> Any:
        attribute = getattr(self._inner, name)
        if name != self._method or self.failed:
            return attribute

        def fail_once(*arguments: Any, **keywords: Any) -> Any:
            self.failed = True
            raise LedgerUnavailable("simulated crash before the ledger step")

        return fail_once
