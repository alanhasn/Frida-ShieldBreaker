# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
