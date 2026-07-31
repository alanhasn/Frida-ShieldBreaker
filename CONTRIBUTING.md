# Contributing to Frida-ShieldBreaker

Thanks for your interest in improving Frida-ShieldBreaker. This document
covers how the project is organized, how to set up a working development
environment, and what's expected of a pull request.

## Ground rules

- This project is for authorized security research and testing only. Do not
  submit contributions whose only purpose is to target a specific named
  application, service, or organization — hooks and heuristics should stay
  generic and reusable across targets. See [SECURITY.md](SECURITY.md) for
  the full policy.
- Keep changes focused. A pull request that fixes a bug or adds one hook
  should not also reformat unrelated files or restructure unrelated modules.
- Prefer tracing over bypassing. Every hook should report what it observed
  via `log`/`event` regardless of whether bypass mode is active. Active
  bypass behavior must stay gated behind `config.bypass` and default to
  off.

## Development setup

```bash
python -m venv venv
source venv/bin/activate      # venv\Scripts\activate on Windows
pip install -r requirements.txt

npm install
npm run build
```

Run `python main.py devices` to confirm the Python side can talk to Frida,
and `npm run typecheck` to confirm the JS agent sources are well-formed.

## Project layout

- `core/` — Python orchestration engine (device/session lifecycle, IPC
  decoding, logging). This layer knows nothing about what any individual
  agent module does; it only moves bytes of JavaScript into a process and
  routes structured messages back out.
- `agents/` — GumJS instrumentation modules, compiled by `frida-compile`
  into a single bundle (`agents/dist/agent.js`) that `core/loader.py`
  injects. Each module lives in its own directory under `agents/` and
  exports a single `init(config)` function; `agents/loader.js` registers it
  and fans out the enabled-module list and per-module config at runtime.
- `agents/common/` — shared helpers used by every module: the IPC envelope
  (`rpc.js`) and cross-platform native/Java/ObjC utilities
  (`native_utils.js`). Module-specific logic does not belong here.

## Adding a new module

1. Create `agents/<module_name>/<module_name>.js` exporting `init(config)`.
2. Register it in `agents/loader.js`'s `MODULE_REGISTRY`.
3. Use `log(moduleName, level, message, extra)` for narrative/debug output
   and `event(moduleName, name, payload)` for discrete findings — never call
   the raw global `send()` directly; both helpers live in
   `agents/common/rpc.js` and keep the envelope shape consistent across
   modules.
4. Wrap native hooks with `attachSafe`/`resolveExport` from
   `agents/common/native_utils.js` so a missing symbol on one OEM/OS build
   logs a warning instead of taking down every other module's hooks.
5. Gate any bypass behavior behind `config.bypass`, defaulting to `false`.
6. Add a toggle for the module in `main.py`'s `--modules` help text and this
   repository's `README.md` module table.

## Coding conventions

- JavaScript agent code targets `es2022` as an ES module (see
  `tsconfig.json`); `npm run typecheck` runs `tsc --noEmit` in
  `allowJs`/non-strict-JS mode purely to catch structural issues (undefined
  imports, obvious type mismatches) — it is not full type-checking.
- Python targets 3.10+, uses `from __future__ import annotations`, and
  favors explicit dataclasses/typed signatures over loosely-typed dicts for
  anything that crosses a function boundary in `core/`.
- Comments should explain *why*, not *what* — a hidden constraint, a
  platform quirk, or the reason a workaround exists. Avoid narrating what
  the code already makes obvious, and avoid referencing specific
  investigations, targets, or issue numbers that won't mean anything to a
  future reader.
- Don't hardcode assumptions (class names, field names, package
  identifiers) that only hold for one application you tested against.
  Prefer reflection/introspection-based fallbacks — see
  `agents/recon/recon.js` for the pattern used when a known field/class
  name may not be present on an obfuscated or unexpected target.
- Don't re-implement a hook another module already has. If a new module
  needs the same underlying technique applied to a different scope (e.g.
  a specific native module rather than a process-wide search), export a
  parameterized entry point from the module that owns the hook instead —
  see `installNativeTlsHooksForModules` in `agents/tls_inspector/tls_inspector.js`
  and its caller in `agents/flutter_tls/flutter_tls.js` for the pattern.

## Before submitting a pull request

```bash
npm run typecheck
npm run build
python -m py_compile main.py core/*.py
```

All three should complete without errors. If you changed CLI flags or
module configuration shapes, update `README.md` accordingly.

## Commit messages

This project follows [Conventional Commits](https://www.conventionalcommits.org/)
(`feat(scope): ...`, `fix(scope): ...`, `docs: ...`, `chore: ...`, etc.).
Keep commits atomic — one logical change per commit.

## Pull requests

- Describe what changed and why, not just what.
- Link any related issue.
- Keep the diff scoped to the described change; unrelated cleanup should be
  its own PR.
