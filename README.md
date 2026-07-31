# Frida-ShieldBreaker

Frida-ShieldBreaker is a modular dynamic analysis and instrumentation
framework for Android and iOS applications, built on top of
[Frida](https://frida.re/). It orchestrates a Python-side session manager
around a single compiled JavaScript agent, giving each instrumentation
concern (filesystem/environment checks, TLS/pinning, anti-debug, runtime
reconnaissance) its own self-contained module while sharing one consistent
IPC, logging, and configuration surface.

It is designed for security researchers and engineers who need to
understand *how* an app detects instrumentation or pins its network traffic
before deciding whether and how to work around it — not to blindly throw
every known bypass at a target.

## Disclaimer

Frida-ShieldBreaker is intended **exclusively** for authorized use: security
research, penetration testing engagements you are contracted or permitted to
perform, CTF competitions, and analysis of applications you own or have
explicit written permission to test. Instrumenting or bypassing protections
in an application without authorization may violate the law and the
application's terms of service. You are solely responsible for how you use
this software. See [SECURITY.md](SECURITY.md) for the project's security
policy.

## Features

- **Single orchestration engine** (`core/`) — resolves a Frida device,
  spawns or attaches to a target process, injects the compiled agent, and
  routes structured messages back to a Rich-formatted console/log.
- **One compiled agent, multiple modules** — every instrumentation module
  is a plain ES module compiled by `frida-compile` into a single GumJS
  bundle, toggled per-run from the CLI without touching code.
- **Trace-first, bypass-opt-in** — every hook reports what it observed
  (`log`/`event` messages) regardless of whether bypassing is enabled.
  Active bypassing is an explicit opt-in (`--bypass` or per-module config),
  so the framework is safe to run as a pure observability tool.
- **Cross-platform hooks** — native (libc / OpenSSL / BoringSSL), Android
  (Java/ART), and iOS (Objective-C) code paths are covered where the
  underlying technique applies to both platforms.
- **Evidence-driven reconnaissance** — the `recon` module enumerates
  loaded classes, auto-discovers unknown detection call chains via stack
  introspection, and reflects on unfamiliar object shapes instead of
  guessing field/method names — useful when a target's detection logic
  isn't covered by a known library or pattern.
- **Flutter-aware TLS scoping** — the `flutter_tls` module identifies
  Flutter's own native engine module at runtime (rather than assuming a
  package layout) and installs native TLS hooks scoped to exactly that
  module, so its statically-linked BoringSSL is covered even when a
  separate system TLS library is also loaded in the same process.
- **Automatic framework detection** (`--auto`) — identifies the target's
  technology stack (Flutter, React Native, Unity, Xamarin, Cordova,
  Capacitor, or native Android) from runtime evidence and enables only
  the modules relevant to it, instead of requiring the user to already
  know which ones apply. See
  [Automatic Framework Detection](#automatic-framework-detection) below.

## Modules

| Module            | Toggle        | Purpose                                                                                                                                                                                                         |
| ----------------- | ------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `fs_monitor`    | `fs`        | Traces (and optionally spoofs) filesystem, package-manager, exec, and system-property checks commonly used for root/jailbreak and developer-mode detection.                                                     |
| `tls_inspector` | `tls`       | Observes and optionally bypasses TLS certificate validation and pinning — Android`TrustManager`/OkHttp/WebView, iOS `SecTrust`/`NSURLSession`, and native OpenSSL/BoringSSL.                             |
| `anti_debug`    | `antidebug` | Traces and optionally neutralizes`ptrace`-based and `/proc`-introspection anti-debugging checks, plus forced self-destruct calls (`exit`/`abort`/`raise`).                                            |
| `recon`         | `recon`     | Diagnostic-only by default; not part of the default module set. Enumerates suspicious classes, hooks common "reaction points," and auto-traces unknown detection call chains with reflection-based diagnostics. |
| `flutter_tls`   | `flutter_tls` | Not part of the default module set. Detects a Flutter runtime, locates its native engine module(s), identifies the bundled OpenSSL/BoringSSL, and installs TLS hooks scoped to those modules — a no-op on non-Flutter targets. |

Each module's hooks are always safe to run in trace-only mode. Bypassing is
gated per-module by `config.bypass` and is off by default.

## Automatic Framework Detection

Passing `--auto` (alias `--detect`) to `run` lets the agent identify the
target's technology stack at runtime and enable only the modules relevant
to it, instead of requiring `--modules` to be set correctly by hand. This
runs entirely inside the injected agent (`agents/framework_detection/`),
once, during the same bootstrap step that otherwise reads `--modules`
directly — an explicit `--modules` always takes precedence over `--auto`.

**How it works.** A registry of per-framework detectors
(`agents/framework_detection/{flutter,react_native,unity,xamarin,cordova,capacitor,native_android}.js`)
each inspect the running process for evidence of their framework:
loaded native modules (e.g. `libflutter.so`, `libil2cpp.so`,
`libmonodroid.so`), Java marker classes (e.g. `io.flutter.embedding.
engine.FlutterEngine`, `com.unity3d.player.UnityPlayer`), and — for
Flutter — a live Dart VM version read via `Dart_VersionString()`. Every
detector runs and reports a result; nothing is decided from a single
signal.

**Confidence scoring.** Each detector's `detect()` returns
`{ framework, confidence, evidence }`, where `confidence` is a 0-100
score built from independently-weighted checks (see
`agents/framework_detection/scoring.js`): each piece of evidence that's
actually present contributes its weight, and `evidence` collects a
human-readable string for each one so the score is always explainable,
not just a number. A framework counts as "detected" once its score
clears a fixed threshold (50). Weights are deliberately front-loaded
onto each framework's single most distinctive marker class, so that
marker alone is enough to cross the threshold — native-library evidence
adds further confidence when available, but isn't required. This
matters because of *when* detection runs: `core/loader.py` spawns a
process suspended and injects the agent before resuming it specifically
so hooks are installed before the app's own early checks fire (see
`core/loader.py`'s `spawn()`), and at that point an Android app's own
Java classes are typically already resolvable via its classloader, while
its own native libraries (loaded via `System.loadLibrary()` during
`Application`/`Activity` initialization) usually are not yet. Native
evidence is most complete when attaching to an already-running process
with `--attach` rather than spawning.

**Evidence collection.** Detection emits structured events through the
same `log`/`event` pipeline every module uses:
`framework_detection_started`, `framework_confidence` and
`framework_evidence` (per detector, regardless of score),
`framework_detected` (only for detectors that cleared the threshold),
`framework_detection_finished`, and `automatic_modules_selected`. All of
these surface through the normal console/log output — no separate
reporting mechanism.

**Automatic module selection.** Which modules a detected framework
enables is a plain lookup table (`FRAMEWORK_MODULE_MAP` in
`agents/framework_detection/detector.js`), not logic embedded in the
detectors:

| Framework | Modules enabled |
|---|---|
| Flutter | `flutter_tls`, `tls`, `recon`, `fs` |
| React Native | `tls`, `recon`, `fs` |
| Unity | `tls`, `recon`, `antidebug` |
| Xamarin | `tls`, `recon`, `fs` |
| Cordova | `tls`, `recon`, `fs` |
| Capacitor | `tls`, `recon`, `fs` |
| Native Android | `tls`, `recon`, `fs`, `antidebug` |

If more than one framework clears the threshold, their module lists are
unioned. If none does, automatic selection falls back to the same
`fs,tls,antidebug` set `run` uses with no flags at all — `--auto` never
enables fewer modules than doing nothing would.

**Adding a new framework detector** requires no changes to the detection
engine itself:

1. Create `agents/framework_detection/<name>.js` exporting `detect()`,
   returning `{ framework, confidence, evidence }` (see any existing
   detector for the pattern; `scoring.js`'s `scoreEvidence` builds the
   score/evidence pair from a list of weighted checks).
2. Import it in `detector.js` and add it to the `DETECTORS` array.
3. Add its module mapping to `FRAMEWORK_MODULE_MAP`.
4. If it's a distinct Android app type, add its most distinctive marker
   class to `native_android.js`'s exclusion list, so "native Android"
   stays an accurate negative signal.

## Requirements

- Python 3.10+
- Node.js 18+ and npm (for building the JS agent bundle)
- A Frida-compatible target device with `frida-server` running (or a local
  target on the same host), matching the `frida`/`frida-tools` versions
  pinned in `requirements.txt`

## Installation

```bash
git clone https://github.com/alanhasn/Frida-ShieldBreaker
cd Frida-ShieldBreaker

# Python side
python -m venv venv
source venv/bin/activate      # venv\Scripts\activate on Windows
pip install -r requirements.txt

# JavaScript agent side
npm install
npm run build                 # produces agents/dist/agent.js
```

## Usage

```bash
# List devices Frida can see
python main.py devices

# List installed applications on a USB-connected device
python main.py apps --usb

# List currently running processes
python main.py ps --usb

# Spawn a target suspended and load every default module (trace-only)
python main.py run com.example.app --usb --spawn \
    --modules fs,tls,antidebug

# Same, but actively bypass every detected check
python main.py run com.example.app --usb --spawn \
    --modules fs,tls,antidebug --bypass

# Attach to an already-running process by package identifier or pid
python main.py run com.example.app --usb --attach

# Run the diagnostic reconnaissance module alongside the rest
python main.py run com.example.app --usb --spawn \
    --modules fs,tls,antidebug,recon

# Against a Flutter target: identify and bypass its own bundled TLS stack
python main.py run com.example.app --usb --spawn \
    --modules fs,tls,antidebug,flutter_tls --bypass

# Let the agent detect the target's framework and pick modules itself
python main.py run com.example.app --usb --spawn --auto --bypass

# Persist structured logs to disk in addition to the console
python main.py run com.example.app --usb --spawn --log-file reports/session.log

# Per-module configuration overrides (escape hatch beyond --bypass)
python main.py run com.example.app --usb --spawn \
    --module-config '{"fs": {"extra_markers": ["myroot"]}}'
```

Run `python main.py run --help` for the full list of flags, including
`--retry-spawn` (retries a spawn that times out on flaky USB/zygote
gating — a known intermittent Frida issue, not a fixed-length timeout this
project controls), `--agent` (point at an alternate compiled bundle), and
`--auto`/`--detect` (see
[Automatic Framework Detection](#automatic-framework-detection)).

## Project Structure

```
frida-shieldbreaker/
├── main.py                  # CLI entry point (devices / apps / ps / run)
├── core/                    # Python orchestration engine
│   ├── loader.py            #   FridaLoader: device/session/process lifecycle
│   ├── ipc.py                #   Decodes agent messages, dispatches by type
│   └── logger.py             #   Rich-backed console + optional file logging
├── agents/                   # JavaScript instrumentation agents (GumJS)
│   ├── loader.js              #   Agent entry point; module registry + bootstrap
│   ├── common/                 #   Shared RPC envelope + native/platform helpers
│   ├── fs_monitor/              #   Filesystem / environment monitoring module
│   ├── tls_inspector/            #   TLS inspection & pinning bypass module
│   ├── anti_debug/                #   Anti-debug diagnostics module
│   ├── recon/                      #   Evidence-driven reconnaissance module
│   ├── flutter_tls/                  #   Flutter-aware native TLS discovery & bypass module
│   ├── framework_detection/           #   Automatic framework detection engine + per-framework detectors
│   └── dist/                        #   Build output (frida-compile bundle, gitignored)
├── native/gum_extensions/    # Reserved for future native Gum extensions
├── config/                   # Reserved for user-supplied configuration profiles
├── reports/                  # Default destination for session logs (gitignored)
└── requirements.txt / package.json
```

## Development

```bash
npm run typecheck   # tsc --noEmit over agents/**/*.js
npm run build       # one-shot production bundle -> agents/dist/agent.js
npm run build:debug # unminified bundle with source maps
npm run watch        # rebuild on save while iterating on a module
```

The Python side has no external build step; run `main.py` directly from the
virtual environment described above.

## Contributing

Contributions are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md) for the
development workflow, coding conventions, and pull request expectations.

## Security

If you believe you've found a vulnerability in Frida-ShieldBreaker itself,
please follow the responsible disclosure process in
[SECURITY.md](SECURITY.md) rather than opening a public issue.

## License

Released under the [MIT License](LICENSE).
