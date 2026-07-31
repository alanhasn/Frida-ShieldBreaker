#!/usr/bin/env python3
"""Frida-ShieldBreaker CLI.

Entry point for authorized dynamic analysis sessions against
Android/iOS targets: enumerates devices/processes, spawns or attaches
to a target, injects the JS instrumentation agent, and streams
structured findings back to the console (and optionally a log file).

Example usage:
    python main.py devices
    python main.py apps --usb
    python main.py run com.example.app --usb --spawn \\
        --modules fs,tls,antidebug --log-file reports/session.log
    python main.py run 1234 --attach --agent agents/dist/agent.js
    python main.py run com.example.app --usb --spawn \\
        --modules fs,tls,antidebug,flutter_tls --bypass
    python main.py run com.example.app --usb --spawn --auto --bypass
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Optional

import frida
from rich.table import Table

from core.loader import AttachedTarget, FridaLoader, LoaderConfig, LoaderError, SpawnTimeoutError
from core.logger import console, get_logger, setup_logging

DEFAULT_AGENT_PATH = Path("agents/dist/agent.js")
DEFAULT_MODULES = "fs,tls,antidebug"

logger = get_logger("cli")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="shieldbreaker",
        description="Frida-ShieldBreaker -- modular dynamic instrumentation for authorized mobile security assessments.",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug-level logging.")
    parser.add_argument("--log-file", type=Path, default=None, help="Persist logs to this file in addition to stdout.")

    subparsers = parser.add_subparsers(dest="command", required=True)

    # --- devices -----------------------------------------------------
    subparsers.add_parser("devices", help="List devices visible to frida-python.")

    # --- apps ----------------------------------------------------------
    apps_parser = subparsers.add_parser("apps", help="List installed applications on a device.")
    _add_device_args(apps_parser)

    # --- ps --------------------------------------------------------------
    ps_parser = subparsers.add_parser("ps", help="List running processes on a device.")
    _add_device_args(ps_parser)

    # --- run -------------------------------------------------------------
    run_parser = subparsers.add_parser("run", help="Spawn or attach to a target and load the instrumentation agent.")
    run_parser.add_argument("target", help="App identifier / bundle id (spawn) or pid/process name (attach).")
    _add_device_args(run_parser)

    mode_group = run_parser.add_mutually_exclusive_group()
    mode_group.add_argument("--spawn", action="store_true", default=True, help="Spawn `target` suspended (default).")
    mode_group.add_argument("--attach", dest="spawn", action="store_false", help="Attach to an already-running `target`.")

    run_parser.add_argument(
        "--agent", type=Path, default=DEFAULT_AGENT_PATH,
        help=f"Path to the compiled JS agent bundle (default: {DEFAULT_AGENT_PATH}).",
    )
    run_parser.add_argument(
        "--modules", type=str, default=None,
        help="Comma-separated module toggles forwarded to the agent's init payload "
             f"(default: {DEFAULT_MODULES}, unless --auto selects modules automatically). "
             "Passing this explicitly always wins over --auto.",
    )
    run_parser.add_argument("--no-resume", action="store_true", help="Load the agent but leave the process suspended.")
    run_parser.add_argument("--kill-on-exit", action="store_true", help="Kill the target on exit (only if we spawned it).")
    run_parser.add_argument(
        "--bypass", action="store_true",
        help="Actively bypass detected checks (spoof return values) instead of only tracing them. "
             "Applies to every enabled module that supports it (fs, tls, antidebug, flutter_tls), "
             "whether enabled explicitly or via --auto.",
    )
    run_parser.add_argument(
        "--module-config", type=str, default=None, metavar="JSON",
        help='Raw JSON merged into each module\'s init config, e.g. \'{"fs": {"extra_markers": ["myroot"]}}\'. '
             "Overrides --bypass on a per-module basis.",
    )
    run_parser.add_argument(
        "--auto", "--detect", dest="auto", action="store_true",
        help="Automatically detect the target's framework (Flutter, React Native, Unity, Xamarin, "
             "Cordova, Capacitor, or native Android) at runtime and enable only the modules relevant "
             "to it, instead of the fixed default set. Ignored if --modules is also given explicitly.",
    )
    run_parser.add_argument(
        "--retry-spawn", type=int, default=1, metavar="N",
        help="Retry up to N times if spawning times out -- this is a known intermittent frida-core/"
             "zygote spawn-gating issue on some devices (frida/frida-core#376), not a fixed-length "
             "client-side timeout we can extend. Default: 1 (no retry).",
    )

    return parser


def _add_device_args(p: argparse.ArgumentParser) -> None:
    device_group = p.add_mutually_exclusive_group()
    device_group.add_argument("--usb", action="store_true", help="Use the first USB-connected device.")
    device_group.add_argument("--device-id", type=str, default=None, help="Explicit frida device id.")
    device_group.add_argument("--remote", type=str, default=None, metavar="HOST:PORT", help="Connect to a remote frida-server.")


def _loader_config_from_args(args: argparse.Namespace) -> LoaderConfig:
    return LoaderConfig(
        device_id=args.device_id,
        use_usb=args.usb,
        remote_host=args.remote,
    )


def cmd_devices(_: argparse.Namespace) -> int:
    table = Table(title="Frida Devices")
    table.add_column("ID", style="cyan")
    table.add_column("Name", style="magenta")
    table.add_column("Type", style="green")

    for device in FridaLoader.list_devices():
        table.add_row(device.id, device.name, device.type)
    console.print(table)
    return 0


def cmd_apps(args: argparse.Namespace) -> int:
    loader = FridaLoader(_loader_config_from_args(args))
    table = Table(title=f"Applications on {loader.device.name}")
    table.add_column("PID", style="cyan")
    table.add_column("Identifier", style="magenta")
    table.add_column("Name", style="green")

    for app in loader.list_applications():
        table.add_row(str(app.pid or "-"), app.identifier, app.name)
    console.print(table)
    return 0


def cmd_ps(args: argparse.Namespace) -> int:
    loader = FridaLoader(_loader_config_from_args(args))
    table = Table(title=f"Processes on {loader.device.name}")
    table.add_column("PID", style="cyan")
    table.add_column("Name", style="magenta")

    for proc in loader.list_processes():
        table.add_row(str(proc.pid), proc.name)
    console.print(table)
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    config = _loader_config_from_args(args)

    # Explicit --modules always wins over --auto; --auto only takes effect
    # when the user hasn't told us exactly what to run.
    explicit_modules = args.modules is not None
    auto_detect = bool(args.auto) and not explicit_modules

    module_config: dict[str, dict] = {}
    if args.module_config:
        try:
            overrides = json.loads(args.module_config)
        except json.JSONDecodeError as exc:
            raise LoaderError(f"--module-config is not valid JSON: {exc}") from exc
        for name, cfg in overrides.items():
            module_config.setdefault(name, {}).update(cfg)

    # default_bypass is applied uniformly by the agent to every module it
    # ends up enabling, whether that list came from enabled_modules below
    # or -- when auto_detect is true -- from the agent's own framework
    # detection, which main.py can't enumerate in advance.
    init_payload = {
        "module_config": module_config,
        "default_bypass": bool(args.bypass),
        "auto_detect": auto_detect,
    }
    if not auto_detect:
        modules_str = args.modules if explicit_modules else DEFAULT_MODULES
        init_payload["enabled_modules"] = [m.strip() for m in modules_str.split(",") if m.strip()]

    with FridaLoader(config) as loader:
        target: AttachedTarget
        if args.spawn:
            for attempt in range(1, args.retry_spawn + 1):
                try:
                    target = loader.spawn(args.target)
                    break
                except SpawnTimeoutError:
                    if attempt >= args.retry_spawn:
                        raise
                    logger.warning("Spawn attempt %d/%d timed out; retrying...", attempt, args.retry_spawn)
        else:
            target_ref = int(args.target) if args.target.isdigit() else args.target
            target = loader.attach(target_ref)

        loader.load_agent(target, args.agent, init_payload=init_payload)

        if args.spawn and not args.no_resume:
            loader.resume(target)

        loader.wait_forever()
        loader.detach(target, kill=args.kill_on_exit and target.spawned_by_us)

    return 0


COMMANDS = {
    "devices": cmd_devices,
    "apps": cmd_apps,
    "ps": cmd_ps,
    "run": cmd_run,
}


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    setup_logging(verbose=args.verbose, log_file=args.log_file)

    console.print(
        "[bold red]Frida-ShieldBreaker[/bold red] -- for use only on targets you own "
        "or are explicitly authorized to test.\n",
    )

    try:
        return COMMANDS[args.command](args)
    except LoaderError as exc:
        logger.error(str(exc))
        return 1
    except frida.InvalidArgumentError as exc:
        logger.error("Invalid argument: %s", exc)
        return 1
    except KeyboardInterrupt:
        logger.warning("Aborted by user.")
        return 130
    except Exception:
        logger.exception("Unhandled error")
        return 1


if __name__ == "__main__":
    sys.exit(main())
