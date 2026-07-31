"""Core Frida orchestration engine for Frida-ShieldBreaker.

`FridaLoader` is the single point of contact with the `frida` Python
bindings: resolving a device, spawning or attaching to a target
process, injecting a (pre-bundled) JS agent, and tearing everything
down cleanly on exit or interrupt.

This module intentionally knows nothing about what the agent scripts
*do* (root-detection tracing, TLS interception, anti-debug diagnostics,
...). It only knows how to get bytes of JavaScript running inside a
target process and how to route messages back out via `core.ipc.IPCBus`.

Intended for authorized dynamic analysis engagements only (pentests,
CTFs, security research on apps you own or have written permission to
test). Nothing here performs the assessment itself -- that logic lives
in the `agents/` JS modules loaded by this class.
"""

from __future__ import annotations

import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional, Union

import frida

from core.ipc import IPCBus
from core.logger import get_logger

logger = get_logger("loader")


class LoaderError(RuntimeError):
    """Raised for any unrecoverable orchestration failure."""


class SpawnTimeoutError(LoaderError):
    """device.spawn() timed out waiting for the app to launch.

    This is a known, intermittent frida-core/zygote spawn-gating issue on
    some devices/ROMs (see frida/frida-core#376) rather than a bug in this
    codebase -- frida-core's spawn watchdog uses a hardcoded timeout with
    no Python-level override. Safe (and often sufficient) to just retry.
    """


@dataclass
class AttachedTarget:
    """Bookkeeping for one instrumented process."""

    pid: int
    identifier: str
    session: frida.core.Session
    script: Optional[frida.core.Script] = None
    spawned_by_us: bool = False
    resumed: bool = False


@dataclass
class LoaderConfig:
    """Connection-level configuration for a `FridaLoader` instance."""

    device_id: Optional[str] = None       # explicit device id, e.g. from `frida-ls-devices`
    use_usb: bool = False                 # shorthand for the first USB-connected device
    remote_host: Optional[str] = None     # host:port for `frida-server` over TCP/frida-portal
    spawn_gating: bool = False            # auto-attach to spawned children (e.g. app relaunch)
    connect_timeout_ms: int = 10_000


class FridaLoader:
    """Manages device resolution, process lifecycle, and agent injection.

    Usage:
        with FridaLoader(LoaderConfig(use_usb=True)) as loader:
            target = loader.spawn("com.example.app")
            loader.load_agent(target, Path("agents/dist/agent.js"))
            loader.resume(target)
            loader.wait_forever()
    """

    def __init__(self, config: Optional[LoaderConfig] = None, ipc: Optional[IPCBus] = None) -> None:
        self.config = config or LoaderConfig()
        self.ipc = ipc or IPCBus()
        self._device: Optional[frida.core.Device] = None
        self._targets: dict[int, AttachedTarget] = {}
        self._device_manager = frida.get_device_manager()

        if self.config.spawn_gating:
            self._device_manager.on("changed", self._on_device_manager_changed)

    # ------------------------------------------------------------------ #
    # Device resolution
    # ------------------------------------------------------------------ #

    @property
    def device(self) -> frida.core.Device:
        if self._device is None:
            self._device = self._resolve_device()
        return self._device

    def _resolve_device(self) -> frida.core.Device:
        try:
            if self.config.remote_host:
                logger.info("Connecting to remote frida-server at %s", self.config.remote_host)
                return self._device_manager.add_remote_device(self.config.remote_host)
            if self.config.device_id:
                logger.info("Resolving device by id: %s", self.config.device_id)
                return self._device_manager.get_device(
                    self.config.device_id, timeout=self.config.connect_timeout_ms // 1000
                )
            if self.config.use_usb:
                logger.info("Resolving first USB-connected device")
                return frida.get_usb_device(timeout=self.config.connect_timeout_ms // 1000)

            logger.info("No device specified; defaulting to local system")
            return frida.get_local_device()
        except frida.ServerNotRunningError as exc:
            raise LoaderError(
                "frida-server is not running on the target device. "
                "Start it (e.g. `adb shell frida-server &`) and retry."
            ) from exc
        except frida.TimedOutError as exc:
            raise LoaderError("Timed out waiting for a device. Is it connected/authorized?") from exc
        except frida.InvalidArgumentError as exc:
            raise LoaderError(f"No device matches id={self.config.device_id!r}") from exc

    @staticmethod
    def list_devices() -> list[frida.core.Device]:
        """Enumerate all devices frida-python currently sees (local/usb/remote)."""
        return frida.enumerate_devices()

    def list_applications(self) -> list[frida.core.Application]:
        """List installed/launchable applications on the resolved device."""
        try:
            return self.device.enumerate_applications()
        except frida.NotSupportedError as exc:
            raise LoaderError("This device does not support application enumeration.") from exc

    def list_processes(self) -> list[frida.core.Process]:
        """List currently running processes on the resolved device."""
        return self.device.enumerate_processes()

    # ------------------------------------------------------------------ #
    # Process lifecycle: spawn / attach / resume / detach
    # ------------------------------------------------------------------ #

    def spawn(
        self,
        identifier: str,
        argv: Optional[list[str]] = None,
        env: Optional[dict[str, str]] = None,
    ) -> AttachedTarget:
        """Spawn `identifier` suspended and attach to it.

        The process is left suspended until `resume()` is called, so the
        agent script can be loaded and its hooks installed before any
        application code runs -- critical for catching early root/debug
        checks that fire during process init.
        """
        logger.info("Spawning target (suspended): %s", identifier)
        try:
            pid = self.device.spawn(identifier, argv=argv, env=env)
        except frida.NotSupportedError as exc:
            raise LoaderError(f"Spawning is not supported on this device/target: {exc}") from exc
        except frida.ExecutableNotFoundError as exc:
            raise LoaderError(f"No such app/binary: {identifier!r}") from exc
        except frida.PermissionDeniedError as exc:
            raise LoaderError(
                f"Permission denied spawning {identifier!r}. Root/frida-server privileges required."
            ) from exc
        except frida.TimedOutError as exc:
            raise SpawnTimeoutError(
                f"Timed out waiting for {identifier!r} to launch (frida-core's spawn-gating watchdog, "
                f"not a fixed-length client timeout). Often transient -- retry, or reboot the device if "
                f"it keeps recurring (see frida/frida-core#376)."
            ) from exc

        session = self._attach_session(pid)
        target = AttachedTarget(pid=pid, identifier=identifier, session=session, spawned_by_us=True)
        self._targets[pid] = target
        logger.info("Spawned pid=%s for %s (suspended)", pid, identifier)
        return target

    def attach(self, target_ref: Union[int, str]) -> AttachedTarget:
        """Attach to an already-running process by pid or process name."""
        logger.info("Attaching to running target: %s", target_ref)
        pid = self._resolve_pid(target_ref) if isinstance(target_ref, str) else target_ref
        session = self._attach_session(pid)
        target = AttachedTarget(pid=pid, identifier=str(target_ref), session=session, spawned_by_us=False)
        self._targets[pid] = target
        logger.info("Attached to pid=%s", pid)
        return target

    def _resolve_pid(self, name: str) -> int:
        # Try the package/bundle identifier first -- Android reports a
        # running process's OS-level `Process.name` as the app's display
        # label, not its package identifier, so matching only against
        # process names silently fails for exactly the identifier most
        # people pass in.
        for app in self.list_applications():
            if app.identifier == name and app.pid:
                return app.pid

        for proc in self.list_processes():
            if proc.name == name:
                return proc.pid

        running = ", ".join(f"{app.identifier} (pid={app.pid}, {app.name!r})" for app in self.list_applications() if app.pid)
        raise LoaderError(
            f"No running process/app identifier {name!r} found on device. "
            f"Currently running: {running or 'none'}. You can also pass a numeric pid directly."
        )

    def _attach_session(self, pid: int) -> frida.core.Session:
        try:
            session = self.device.attach(pid)
        except frida.ProcessNotFoundError as exc:
            raise LoaderError(f"No such process: pid={pid}") from exc
        except frida.PermissionDeniedError as exc:
            raise LoaderError(f"Permission denied attaching to pid={pid}: {exc}") from exc
        except frida.TimedOutError as exc:
            raise LoaderError(
                f"Timed out attaching to pid={pid}. Usually a flaky device/USB link -- try again or "
                f"restart frida-server on the device."
            ) from exc

        session.on("detached", lambda reason, crash=None: self._on_session_detached(pid, reason, crash))
        return session

    def resume(self, target: AttachedTarget) -> None:
        """Resume a process previously spawned suspended."""
        if target.resumed:
            return
        try:
            self.device.resume(target.pid)
            target.resumed = True
            logger.info("Resumed pid=%s", target.pid)
        except frida.ProcessNotFoundError as exc:
            raise LoaderError(f"Cannot resume; pid={target.pid} no longer exists.") from exc

    def _on_session_detached(self, pid: int, reason: str, crash: Any) -> None:
        level = logger.info if reason == "application-requested" else logger.warning
        level("Session for pid=%s detached: reason=%s%s", pid, reason, f" crash={crash}" if crash else "")
        self._targets.pop(pid, None)

    def _on_device_manager_changed(self) -> None:
        logger.debug("Device topology changed")

    # ------------------------------------------------------------------ #
    # Agent injection
    # ------------------------------------------------------------------ #

    def load_agent(
        self,
        target: AttachedTarget,
        script_path: Path,
        init_payload: Optional[dict[str, Any]] = None,
    ) -> frida.core.Script:
        """Load a (pre-bundled) JS agent into `target` and wire up IPC.

        `script_path` is expected to be a single-file bundle -- e.g. the
        output of running `npm run build` (frida-compile) against
        `agents/loader.js`, which composes the fs_monitor, tls_inspector
        and anti_debug modules into one bundle. This method does not care
        how the bundle was produced, only that it is valid Frida GumJS.
        """
        if not script_path.exists():
            raise LoaderError(
                f"Agent bundle not found: {script_path}. "
                f"Did you run the JS build (e.g. `npm run build` in agents/)?"
            )

        source = script_path.read_text(encoding="utf-8")
        try:
            script = target.session.create_script(source, name=script_path.stem)
        except frida.InvalidOperationError as exc:
            raise LoaderError(f"Session for pid={target.pid} is no longer valid: {exc}") from exc

        script.on("message", self.ipc.dispatch)
        script.on("destroyed", lambda: logger.warning("Agent script for pid=%s was destroyed", target.pid))

        try:
            script.load()
        except frida.core.RPCException as exc:
            raise LoaderError(f"Agent script failed during load(): {exc}") from exc

        if init_payload is not None:
            # Convention: agents/common/rpc.js registers a top-level
            # recv('init', ...) handler that toggles which sub-modules run.
            script.post({"type": "init", "payload": init_payload})

        target.script = script
        logger.info("Agent loaded into pid=%s (%s)", target.pid, script_path.name)
        return script

    # ------------------------------------------------------------------ #
    # Lifecycle / cleanup
    # ------------------------------------------------------------------ #

    def wait_forever(self, poll_interval: float = 0.5) -> None:
        """Block until interrupted, keeping the process alive for hooks to fire."""
        logger.info("Instrumentation active. Press Ctrl+C to detach and exit.")
        try:
            while True:
                time.sleep(poll_interval)
        except KeyboardInterrupt:
            logger.info("Interrupt received, detaching...")

    def detach(self, target: AttachedTarget, kill: bool = False) -> None:
        """Detach a single target's session, optionally killing the process."""
        try:
            if target.script is not None:
                target.script.unload()
        except (frida.InvalidOperationError, frida.core.RPCException):
            pass  # already gone

        try:
            target.session.detach()
        except frida.InvalidOperationError:
            pass  # already detached

        if kill:
            try:
                self.device.kill(target.pid)
            except frida.ProcessNotFoundError:
                pass

        self._targets.pop(target.pid, None)

    def cleanup(self, kill_spawned: bool = False) -> None:
        """Detach every tracked target. Only kills processes we spawned."""
        for pid, target in list(self._targets.items()):
            self.detach(target, kill=kill_spawned and target.spawned_by_us)
        logger.debug("Cleanup complete; %d target(s) released.", len(self._targets))

    def __enter__(self) -> "FridaLoader":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.cleanup(kill_spawned=exc_type is not None)
