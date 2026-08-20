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
7. If the module needs to be driven interactively during a live session
   rather than just configured once at `init()` (see `stalker_tracer` for
   the pattern), expose Frida's own global `rpc.exports` -- **not**
   `agents/common/rpc.js`'s `rpc` helper, which only ever exports
   `log`/`event`/`ready`/`on`/`once`; import that as
   `{ log, event }` specifically to avoid shadowing the global. Extend
   `main.py`'s `--interactive` shell grammar to reach it from Python.

## Adding a new framework detector

`agents/framework_detection/` identifies the target's technology stack so
`--auto` can enable the relevant modules automatically (see the
[README's Automatic Framework Detection section](README.md#automatic-framework-detection)
for how the engine and scoring work). To add a new one:

1. Create `agents/framework_detection/<name>.js` exporting `detect()`,
   returning `{ framework, confidence, evidence }`. Build the score with
   `scoreEvidence()` from `./scoring.js`, given a list of
   `{ present, weight, label }` checks — don't compute confidence by hand.
2. Weight your single most distinctive marker (a class or native module
   name unique to that framework) heavily enough to cross the detection
   threshold (50) on its own. Native-library evidence may not be
   available yet when detection runs (see the README section above for
   why) — don't rely on it being present.
3. Import your `detect()` in `detector.js` and add it to the `DETECTORS`
   array.
4. Add a `framework: [module, ...]` entry to `FRAMEWORK_MODULE_MAP` in
   `detector.js`, and document it in `README.md`'s automatic-selection
   table.
5. If the new framework only applies to Android, add its primary marker
   class to `native_android.js`'s exclusion list so "native Android"
   stays accurate.

Detectors must never throw (`detector.js` catches and logs regardless,
but a well-behaved detector degrades to `confidence: 0` on its own) and
must never install a hook — detection is evidence-only; the modules it
selects are what actually instrument anything.

## Adding a new report interpreter

`core/report/` (see the
[README's Session Reports section](README.md#session-reports)) turns
every module's `event` messages into JSON/HTML/DOCX reports. A new event
name works in a report with no changes at all (it falls back to a
generic description), but reads much better with its own interpreter:

1. In `core/report/interpreters.py`, write a `_describe_<event_name>(payload)`
   function returning `(title, description, severity)`. Use the actual
   field names that event's `event(MODULE_NAME, "name", {...})` call in
   the agent sends — check the JS source, don't guess the shape.
2. Add `"event_name": (category, _describe_<event_name>)` to
   `INTERPRETERS`. Reuse an existing category from `CATEGORY_TITLES` in
   `core/report/model.py` if the new event fits one; only add a new
   category for something genuinely distinct.
3. Severity is one of `"high"` (a real bypass, or comparably significant),
   `"medium"` (observed or an automatic action), `"low"` (a minor
   diagnostic gap), or `"info"` (purely descriptive).

Nothing else (the collector, the renderers) needs to change.

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
python -m py_compile main.py core/*.py core/report/*.py
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
