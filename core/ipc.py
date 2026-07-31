"""IPC message bus between injected JS agents and the Python host.

Every agent module (fs_monitor, tls_inspector, anti_debug, ...) talks to
Python exclusively through `send({type, module, ...payload})`. This
module decodes that envelope and dispatches it to whatever handler was
registered for its `type`, so `core/loader.py` never has to know the
shape of any individual module's payloads.

Wire format (JS -> Python), sent via Frida's `send()`:
    {
        "type": "log" | "event" | "error" | "ready" | <custom>,
        "module": "tls_inspector" | "fs_monitor" | "anti_debug" | ...,
        "payload": { ... arbitrary, module-defined ... }
    }
"""

from __future__ import annotations

import json
from collections import defaultdict
from typing import Any, Callable, DefaultDict, List

from core.logger import get_logger

logger = get_logger("ipc")

MessageHandler = Callable[[str, dict[str, Any]], None]

_LEVEL_MAP = {
    "debug": logger.debug,
    "info": logger.info,
    "warning": logger.warning,
    "warn": logger.warning,
    "error": logger.error,
    "critical": logger.critical,
}


class IPCBus:
    """Routes decoded agent messages to registered handlers by `type`."""

    def __init__(self) -> None:
        self._handlers: DefaultDict[str, List[MessageHandler]] = defaultdict(list)
        self._register_builtins()

    def on(self, message_type: str, handler: MessageHandler) -> None:
        """Register `handler(module, payload)` for a given envelope `type`."""
        self._handlers[message_type].append(handler)

    def dispatch(self, message: dict[str, Any], data: bytes | None) -> None:
        """Entry point for Frida's `session.on('message', ...)` callback.

        Args:
            message: The raw dict Frida hands back (already JSON-decoded
                by frida-python). May be a `send` payload or a `send`
                error/exception envelope.
            data: Optional raw binary companion payload (e.g. dumped
                TLS buffers), passed through untouched to handlers.
        """
        if message.get("type") == "error":
            # Uncaught exception inside the injected agent itself.
            logger.error(
                "[agent runtime error] %s\n%s",
                message.get("description", "unknown error"),
                message.get("stack", ""),
            )
            return

        payload_envelope = message.get("payload")
        if not isinstance(payload_envelope, dict):
            logger.debug("Malformed IPC envelope (no dict payload): %s", message)
            return

        msg_type = payload_envelope.get("type", "unknown")
        module = payload_envelope.get("module", "unknown")
        payload = payload_envelope.get("payload", {})

        if data is not None:
            payload = {**payload, "_raw": data}

        for handler in self._handlers.get(msg_type, ()):
            try:
                handler(module, payload)
            except Exception:
                logger.exception(
                    "IPC handler for type=%s module=%s raised", msg_type, module
                )

        if msg_type not in self._handlers:
            logger.debug("No handler for IPC type=%s (module=%s): %s", msg_type, module, payload)

    def _register_builtins(self) -> None:
        self.on("log", self._handle_log)
        self.on("ready", self._handle_ready)
        self.on("event", self._handle_event)

    @staticmethod
    def _handle_log(module: str, payload: dict[str, Any]) -> None:
        level = str(payload.get("level", "info")).lower()
        text = payload.get("message", "")
        emit = _LEVEL_MAP.get(level, logger.info)
        emit("[%s] %s", module, text)

    @staticmethod
    def _handle_ready(module: str, payload: dict[str, Any]) -> None:
        logger.info("[%s] agent module ready %s", module, json.dumps(payload) if payload else "")

    @staticmethod
    def _handle_event(module: str, payload: dict[str, Any]) -> None:
        # Structured findings (e.g. "a root-detection path check fired") --
        # surfaced at WARNING so they stand out from routine `log` chatter.
        name = payload.get("name", "event")
        details = {k: v for k, v in payload.items() if k != "name"}
        logger.warning("[%s] FINDING %s: %s", module, name, json.dumps(details, default=str))
