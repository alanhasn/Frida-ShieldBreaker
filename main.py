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
    python main.py run com.example.app --usb --spawn --auto --bypass \\
        --report reports/session --report-format json,html,docx
    python main.py run com.example.app --usb --spawn --modules stalker_tracer --interactive
"""

from __future__ import annotations

import argparse
import json
import shlex
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import frida
from rich.table import Table

from core.loader import AttachedTarget, FridaLoader, LoaderConfig, LoaderError, SpawnTimeoutError
from core.logger import console, get_logger, setup_logging
from core.report import ReportCollector, SUPPORTED_FORMATS, SessionMeta, write_reports

DEFAULT_AGENT_PATH = Path("agents/dist/agent.js")
DEFAULT_MODULES = "fs,tls,antidebug"

logger = get_logger("cli")


def _read_tool_version() -> str:
    """Best-effort read of package.json's version -- one project version shared across the Python/JS split."""
    try:
        with open("package.json", encoding="utf-8") as f:
            return str(json.load(f).get("version", "unknown"))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        return "unknown"


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
    run_parser.add_argument(
        "--report", type=Path, default=None, metavar="PATH",
        help="Generate a session report at PATH after the session ends (the appropriate extension is "
             "added per format, e.g. PATH.json/.html/.docx). Formats controlled by --report-format.",
    )
    run_parser.add_argument(
        "--report-format", type=str, default=",".join(SUPPORTED_FORMATS), metavar="FORMATS",
        help=f"Comma-separated report formats to generate when --report is set "
             f"(default: all -- {', '.join(SUPPORTED_FORMATS)}).",
    )
    run_parser.add_argument(
        "-i", "--interactive", action="store_true",
        help="Drop into an interactive shell instead of blocking silently until Ctrl+C. Lets you "
             "drive stalker_tracer's RPC exports live (start/stop/inspect a native trace against a "
             "running thread) -- type 'help' once connected. No effect on any other module.",
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


_INTERACTIVE_HELP = """\
Commands:
  stalker start --thread ID [--modules m1,m2] [--filter all|syscalls|calls] [--js]
                              Start a native trace on OS thread ID.
                              --modules scopes tracing (and excludes every other
                              loaded module from instrumentation, the main lever
                              against freezing the app); omit to trace everything
                              (expensive). --filter defaults to all instructions;
                              'syscalls' matches svc, 'calls' matches branch/call
                              mnemonics. --js forces the slower pure-JS fallback
                              instead of the native CModule hot path.
  stalker stop [ID]          Stop tracing thread ID (or the only active session
                              if exactly one is running).
  stalker status              Show active trace sessions and CModule availability.
  stalker drain ID [MAX]      Pull up to MAX (default 500) buffered hits from
                              thread ID's session and report a frequency summary.
  stalker threads              List OS thread ids Frida can see right now.
  help                        Show this text.
  quit / exit                 Detach and end the session (same as Ctrl+C).
"""


def _build_interactive_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="stalker", add_help=False, exit_on_error=False)
    sub = parser.add_subparsers(dest="subcommand")

    start = sub.add_parser("start", add_help=False, exit_on_error=False)
    start.add_argument("--thread", type=int, required=True)
    start.add_argument("--modules", type=str, default="")
    start.add_argument("--filter", type=str, default="all")
    start.add_argument("--js", action="store_true")

    stop = sub.add_parser("stop", add_help=False, exit_on_error=False)
    stop.add_argument("thread", type=int, nargs="?")

    sub.add_parser("status", add_help=False, exit_on_error=False)
    sub.add_parser("threads", add_help=False, exit_on_error=False)

    drain = sub.add_parser("drain", add_help=False, exit_on_error=False)
    drain.add_argument("thread", type=int)
    drain.add_argument("max", type=int, nargs="?", default=500)

    return parser


def _dispatch_stalker_command(exports: Any, tokens: list[str]) -> None:
    parser = _build_interactive_parser()
    try:
        args = parser.parse_args(tokens)
    except argparse.ArgumentError as exc:
        console.print(f"[red]{exc}[/red]")
        return
    except SystemExit:
        # exit_on_error=False covers most argparse failure paths, but not
        # every one (e.g. an invalid subcommand name in some Python
        # versions) -- caught here too so a mistyped command never kills
        # the whole interactive session.
        console.print("[red]Invalid command -- type 'help'.[/red]")
        return

    if args.subcommand == "start":
        modules = [m.strip() for m in args.modules.split(",") if m.strip()]
        result = exports.stalker_start(
            {"threadId": args.thread, "modules": modules, "filter": args.filter, "native": not args.js}
        )
        console.print(result)
    elif args.subcommand == "stop":
        thread_id = args.thread
        if thread_id is None:
            sessions = exports.stalker_status()["activeSessions"]
            if len(sessions) != 1:
                console.print("[yellow]Specify a thread id -- more or less than one session is active.[/yellow]")
                return
            thread_id = sessions[0]["threadId"]
        console.print(exports.stalker_stop(thread_id))
    elif args.subcommand == "status":
        console.print(exports.stalker_status())
    elif args.subcommand == "drain":
        console.print(exports.stalker_drain(args.thread, args.max))
    elif args.subcommand == "threads":
        console.print(exports.stalker_list_threads())
    else:
        console.print("Unknown stalker command -- type 'help'.")


def _run_interactive_shell(target: AttachedTarget) -> None:
    """Minimal stdin REPL for calling agent RPC exports (currently: stalker_tracer) during a live session."""
    exports = target.script.exports_sync
    console.print("[bold]Interactive mode.[/bold] Type 'help' for commands, 'quit' to detach and exit.")
    while True:
        try:
            line = input("shieldbreaker> ").strip()
        except (EOFError, KeyboardInterrupt):
            console.print()
            break

        if not line:
            continue
        if line in ("quit", "exit"):
            break
        if line == "help":
            console.print(_INTERACTIVE_HELP)
            continue

        try:
            tokens = shlex.split(line)
        except ValueError as exc:
            console.print(f"[red]Could not parse command: {exc}[/red]")
            continue
        if not tokens or tokens[0] != "stalker":
            console.print("Unknown command -- type 'help'.")
            continue

        try:
            _dispatch_stalker_command(exports, tokens[1:])
        except frida.core.RPCException as exc:
            logger.error("RPC call failed: %s", exc)
        except Exception:
            logger.exception("Interactive command failed")


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

    report_collector: Optional[ReportCollector] = None
    session_meta: Optional[SessionMeta] = None

    with FridaLoader(config) as loader:
        if args.report:
            report_collector = ReportCollector()
            report_collector.attach(loader.ipc)

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

        if args.report:
            session_meta = SessionMeta(
                target=target.identifier,
                device_name=loader.device.name,
                started_at=datetime.now(timezone.utc),
                modules_requested=list(init_payload.get("enabled_modules", [])),
                auto_detect=auto_detect,
                bypass_requested=bool(args.bypass),
                agent_path=str(args.agent),
                tool_version=_read_tool_version(),
            )

        loader.load_agent(target, args.agent, init_payload=init_payload)

        if args.spawn and not args.no_resume:
            loader.resume(target)

        if args.interactive:
            _run_interactive_shell(target)
        else:
            loader.wait_forever()
        loader.detach(target, kill=args.kill_on_exit and target.spawned_by_us)

    if args.report and report_collector is not None and session_meta is not None:
        session_meta.ended_at = datetime.now(timezone.utc)
        try:
            report = report_collector.build_report(session_meta)
            formats = [f.strip() for f in args.report_format.split(",") if f.strip()]
            for path in write_reports(report, args.report, formats=formats):
                logger.info("Report written: %s", path)
        except Exception:
            logger.exception("Failed to generate report(s); session data itself was not affected")

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
