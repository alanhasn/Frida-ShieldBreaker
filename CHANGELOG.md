# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.5.0] - 2026-08-02

### Added

- **`stalker_tracer` module**: native instruction tracing via Frida's
  Stalker, with the hot path (agents/stalker_tracer/native_source.js)
  compiled at runtime through CModule directly into the target process
  for zero-JS-overhead per-instruction callouts, falling back to a
  pure-JS callout automatically if CModule compilation is unavailable.
  Traces a specific OS thread's actual execution path -- code with no
  exported symbol to hook (OLLVM/flattened control flow, inlined
  routines, raw `svc` syscalls) is now reachable. Module-name-based
  range filtering plus `Stalker.exclude()` on every other loaded module
  keeps instrumentation scoped and the target responsive. Instruction
  filtering presets: `all`, `syscalls` (`svc`), `calls` (branch/call
  mnemonics), or an explicit mnemonic list.
- **RPC-driven interactive control**: unlike every other module,
  `stalker_tracer` does nothing from `init()` on its own -- it's driven
  live via Frida's own `rpc.exports` (`stalkerStart`/`Stop`/`Status`/
  `Drain`/`ListThreads`/`Capabilities`). `config.auto_start` (via
  `--module-config`) covers non-interactive/scripted use.
- **CLI**: `-i`/`--interactive` on `run` -- replaces the usual silent
  block-until-Ctrl+C with a small stdin REPL (`stalker start/stop/
  status/drain/threads`) calling `target.script.exports_sync` live.
- **Reports**: a new "Native Instruction Tracing" category and
  interpreters for all six `stalker_tracer` event types.

No behavior change when `stalker_tracer` isn't in `--modules` and
`--interactive` isn't passed.

## [0.4.0] - 2026-08-02

### Added

- **Session reports** (`core/report/`): `--report PATH` on `run` generates
  a JSON, HTML, and/or DOCX report (`--report-format`, default all three)
  from the same `log`/`event`/`ready` IPC stream every module already
  emits -- no module changes required. A collector accumulates every
  event as a `Finding`; an interpreter registry
  (`core/report/interpreters.py`) turns each into a human-readable
  title/description/category/severity, covering every event type
  currently emitted across fs_monitor, tls_inspector, anti_debug, recon,
  flutter_tls, and framework_detection, with a generic fallback for
  anything unregistered. Reports include an executive summary, session
  details, a findings-per-category breakdown, and detailed per-category
  findings tables. Adding report support for a new event type is a
  one-entry addition to the interpreter registry; no other code changes.
- `python-docx` dependency for the DOCX renderer (imported lazily, so
  JSON/HTML report generation never requires it).
- Agent `ready` payload now includes `platform`/`arch` (previously only
  in a free-text log line), used to populate report session metadata.

No behavior change when `--report` isn't passed: no collector is
attached and no report code runs.

## [0.3.0] - 2026-08-01

### Added

- **Automatic framework detection** (`agents/framework_detection/`): a
  registry of per-framework detectors (Flutter, React Native, Unity,
  Xamarin, Cordova, Capacitor, native Android) that each report a 0-100
  confidence score and human-readable evidence from loaded native
  modules, Java marker classes, and (for Flutter) a live Dart VM version
  read. Detected frameworks map to the modules to auto-enable via a
  plain, editable lookup table rather than logic embedded in the
  detectors, so extending coverage or changing a mapping never touches
  detection code. Emits structured diagnostics
  (`framework_detection_started`/`_finished`, `framework_confidence`,
  `framework_evidence`, `framework_detected`, `automatic_modules_selected`)
  through the existing log/event pipeline. Runs once per process
  (memoized) at the same bootstrap point every module's `init()` already
  runs from.
- **CLI**: `--auto` (alias `--detect`) on `run`. Enables automatic module
  selection instead of the fixed default set; an explicit `--modules`
  always takes precedence. `--bypass` now applies uniformly to whatever
  gets enabled, whether from `--modules` or from automatic detection.

### Changed

- `agents/loader.js`'s `bootstrap()` selects its module list from
  `framework_detection` when the init payload's `auto_detect` flag is
  set; behavior when it's unset is unchanged. Per-module config is now
  built as `{ bypass: defaultBypass, ...moduleConfig[name] }` uniformly,
  replacing the previous Python-side per-module bypass population loop
  (which couldn't have enumerated an auto-detected module list in
  advance anyway). Existing `--modules`/`--bypass`/`--module-config`
  combinations produce identical effective configs to before.

## [0.2.0] - 2026-07-31

### Added

- **`flutter_tls` module**: Flutter-aware TLS discovery and bypass, opt-in
  (not part of the default module set). Detects a Flutter runtime via
  Java embedding markers and native engine module discovery
  (`libflutter.so`/`libapp.so`, or the iOS `Flutter`/`App` frameworks);
  identifies the bundled OpenSSL/BoringSSL by probing for known export
  names within those specific modules; reads the running Dart VM version
  via `Dart_VersionString()`; and installs TLS hooks scoped to exactly
  the discovered engine module(s) through an explicit, extensible
  bypass-strategy registry. Cross-references Java-visible networking
  (OkHttp/TrustManager) rather than duplicating those hooks. Entirely a
  no-op on non-Flutter targets.
- `agents/common/native_utils.js`: `findModules` (candidate-name module
  lookup) and `readCString`, generic infrastructure used by the new
  module and available to any future one.

### Changed

- `agents/tls_inspector/tls_inspector.js`: the native OpenSSL/BoringSSL
  hooks can now be scoped to a specific list of module-name candidates
  via the new `installNativeTlsHooksForModules` export, instead of only
  the process-wide wildcard search. Existing behavior (`init()`) is
  unchanged.

## [0.1.0] - 2026-07-31

Initial public release.

### Added

- **Core orchestration engine** (`core/`): device resolution (local/USB/
  remote), process spawn/attach with suspended-spawn support, agent
  injection, and structured IPC dispatch, backed by a Rich-formatted
  console and optional file logger.
- **CLI** (`main.py`): `devices`, `apps`, `ps`, and `run` subcommands, with
  `--spawn`/`--attach`, `--modules`, `--bypass`, `--module-config`,
  `--retry-spawn`, `--agent`, `--log-file`, and device-selection flags
  (`--usb`, `--device-id`, `--remote`).
- **Agent build pipeline**: `frida-compile`-based bundling of the
  JavaScript instrumentation agents into a single injectable payload, with
  `build`, `build:debug`, `watch`, and `typecheck` npm scripts.
- **`fs_monitor` module**: native (libc), Android (Java/ART), and iOS
  (Objective-C) hooks for filesystem, package-manager, process-exec, and
  system-property checks used for root/jailbreak and developer-mode
  detection, with opt-in active bypass.
- **`tls_inspector` module**: TLS/SSL-pinning observability and optional
  bypass across Android (`TrustManager` substitution, OkHttp
  `CertificatePinner`, `WebViewClient`), iOS (`SecTrust`,
  `NSURLSession` auth-challenge handling), and native OpenSSL/BoringSSL.
- **`anti_debug` module**: `ptrace`-based and `/proc`-introspection
  anti-debugging trace/bypass, plus neutralization of forced
  self-destruct calls (`exit`/`abort`/`raise`).
- **`recon` module**: evidence-driven reconnaissance for detection paths
  not covered by a known library or pattern — suspicious loaded-class
  enumeration (own-package, cross-platform framework markers, known RASP
  SDK prefixes, generic keyword matches), common "reaction point" hooks,
  generic library method tracing with automatic caller discovery,
  reflection-based object-shape diagnostics, and Flutter `MethodChannel`
  call/reply visibility.
- Project documentation: README, contribution guidelines, security policy,
  and code of conduct.
