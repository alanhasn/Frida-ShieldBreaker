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

## Modules

| Module            | Toggle        | Purpose                                                                                                                                                                                                         |
| ----------------- | ------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `fs_monitor`    | `fs`        | Traces (and optionally spoofs) filesystem, package-manager, exec, and system-property checks commonly used for root/jailbreak and developer-mode detection.                                                     |
| `tls_inspector` | `tls`       | Observes and optionally bypasses TLS certificate validation and pinning — Android`TrustManager`/OkHttp/WebView, iOS `SecTrust`/`NSURLSession`, and native OpenSSL/BoringSSL.                             |
| `anti_debug`    | `antidebug` | Traces and optionally neutralizes`ptrace`-based and `/proc`-introspection anti-debugging checks, plus forced self-destruct calls (`exit`/`abort`/`raise`).                                            |
| `recon`         | `recon`     | Diagnostic-only by default; not part of the default module set. Enumerates suspicious classes, hooks common "reaction points," and auto-traces unknown detection call chains with reflection-based diagnostics. |

Each module's hooks are always safe to run in trace-only mode. Bypassing is
gated per-module by `config.bypass` and is off by default.

## Requirements

- Python 3.10+
- Node.js 18+ and npm (for building the JS agent bundle)
- A Frida-compatible target device with `frida-server` running (or a local
  target on the same host), matching the `frida`/`frida-tools` versions
  pinned in `requirements.txt`

## Installation

```bash
git clone <this-repository>
cd frida-shieldbreaker

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

# Persist structured logs to disk in addition to the console
python main.py run com.example.app --usb --spawn --log-file reports/session.log

# Per-module configuration overrides (escape hatch beyond --bypass)
python main.py run com.example.app --usb --spawn \
    --module-config '{"fs": {"extra_markers": ["myroot"]}}'
```

Run `python main.py run --help` for the full list of flags, including
`--retry-spawn` (retries a spawn that times out on flaky USB/zygote
gating — a known intermittent Frida issue, not a fixed-length timeout this
project controls) and `--agent` (point at an alternate compiled bundle).

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
