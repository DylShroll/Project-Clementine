"""
AI subsystem for Project Clementine.

Two Anthropic-backed capabilities live here:

* :mod:`clementine.ai.triage` — per-finding confidence scoring and
  false-positive flagging (runs between Phase 3 and Phase 4).
* :mod:`clementine.ai.discovery` — novel attack-chain discovery from the
  set of findings the rule-based correlator could not match.

Both modules share the :class:`ClaudeClient` defined in
:mod:`clementine.ai.client`, which owns rate-limit/retry behaviour and
prompt-caching defaults.
"""

from .client import ClaudeClient, ClaudeUnavailable

__all__ = ["ClaudeClient", "ClaudeUnavailable"]
