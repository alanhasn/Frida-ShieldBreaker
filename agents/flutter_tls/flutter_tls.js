// Module: Flutter TLS Inspection & Pinning Bypass.
//
// Flutter apps bundle their own Dart runtime and, with it, a statically
// linked copy of BoringSSL inside the app's own native library (Android:
// libflutter.so and/or libapp.so; iOS: the Flutter and App frameworks).
// dart:io's networking stack talks to that bundled copy directly, which
// means the platform TLS stack tls_inspector's Java/ObjC hooks target
// (TrustManager, OkHttp, SecTrust, NSURLSession, ...) is never involved
// for a Flutter app's own HTTP traffic -- those hooks simply have
// nothing to intercept.
//
// This module doesn't re-implement TLS hooking: it identifies whether a
// Flutter runtime is present at all, locates the specific native
// module(s) that make up its engine, confirms which native TLS entry
// points that module actually exports, and -- only once all of that is
// known -- asks tls_inspector to install its existing native hooks
// scoped to exactly those modules (see installNativeTlsHooksForModules
// in ../tls_inspector/tls_inspector.js). Every step is driven by runtime
// discovery (loaded-module enumeration, export presence, embedder API
// calls); nothing here assumes a specific application, package name, or
// Flutter engine build.
//
// Entirely a no-op on a non-Flutter target: detection fails fast and no
// hooks are installed, so enabling this module has no cost or effect
// outside its intended scope.

import { log, event } from "../common/rpc.js";
import { isAndroid, isIOS, findModules, readCString } from "../common/native_utils.js";
import { installNativeTlsHooksForModules } from "../tls_inspector/tls_inspector.js";

const MODULE_NAME = "flutter_tls";

let bypassEnabled = false;

// Stable, version-independent markers of a Flutter runtime being present.
// Any one of these existing is sufficient evidence -- they're checked by
// simple presence (Java.use() succeeding), not by inspecting behavior, so
// they don't depend on a particular embedding API shape.
const FLUTTER_JAVA_MARKER_CLASSES = [
    "io.flutter.embedding.engine.FlutterEngine",
    "io.flutter.plugin.common.MethodChannel",
    "io.flutter.view.FlutterNativeView", // legacy (pre-embedding-v2) engine entry point
];

// Default candidates for Flutter's own native library across platforms.
// libflutter.so is the engine itself (Dart VM + BoringSSL); libapp.so is
// the compiled Dart AOT snapshot for release/profile builds and may not
// be present at all in JIT/debug builds. Flutter/App are the equivalent
// iOS framework binary names as Frida reports them once loaded -- "App"
// is iOS-only, never checked on Android: confirmed live against a real
// (non-Flutter) Android target that as a bare three-letter substring it
// matches far too much unrelated system-library noise there
// (app_process64, libappfuse.so, any module with "mapper" in its name)
// to be a usable signal.
const DEFAULT_ENGINE_MODULE_NAMES = ["libflutter.so", "libapp.so", "Flutter"];
const IOS_ONLY_ENGINE_MODULE_NAMES = ["App"];

/** Presence-only check for well-known Flutter embedding classes. Android-only; must run inside Java.perform. */
function detectFlutterJavaMarkers() {
    const found = [];
    for (const className of FLUTTER_JAVA_MARKER_CLASSES) {
        try {
            Java.use(className);
            found.push(className);
        } catch (e) {
            // Not present in this app -- not evidence of anything, try the next marker.
        }
    }
    return found;
}

/** Locates Flutter's own native module(s), if any, honoring extra candidates supplied via config. */
function discoverEngineModules(extraModuleNames) {
    const platformCandidates = isIOS() ? [...DEFAULT_ENGINE_MODULE_NAMES, ...IOS_ONLY_ENGINE_MODULE_NAMES] : DEFAULT_ENGINE_MODULE_NAMES;
    const candidates = [...platformCandidates, ...extraModuleNames];
    return findModules(candidates);
}

/**
 * Dart_VersionString() is part of Dart's stable embedder API (dart_api.h),
 * present in every Flutter engine build regardless of Flutter version --
 * unlike parsing a Flutter/engine version out of strings or file layout,
 * calling the real exported function is guaranteed to reflect the actual
 * running Dart VM rather than a guess. Best-effort: absence isn't an
 * error, just a less-capable engine build or an unexpected module layout.
 */
function inspectDartRuntime(engineModules) {
    for (const mod of engineModules) {
        let address;
        try {
            address = Module.findExportByName(mod.name, "Dart_VersionString");
        } catch (e) {
            continue;
        }
        if (address === null || address === undefined) continue;

        try {
            const dartVersionString = new NativeFunction(address, "pointer", []);
            const version = readCString(dartVersionString());
            event(MODULE_NAME, "dart_runtime_detected", { module: mod.name, dart_version: version });
            return;
        } catch (e) {
            log(MODULE_NAME, "debug", `Dart_VersionString call failed on ${mod.name}: ${e.stack || e}`);
        }
    }
    log(MODULE_NAME, "debug", "Dart_VersionString not found in any discovered engine module");
}

// --------------------------------------------------------------------
// Java-path cross-reference
// --------------------------------------------------------------------

// Presence of any of these indicates the app also has a Java-visible
// networking path available (e.g. a plugin that shells out to platform
// HTTP APIs instead of dart:io) -- tls_inspector's Android hooks already
// install unconditionally on every Android target, so that path is
// already covered without this module hooking anything itself.
const JAVA_TLS_MARKER_CLASSES = ["okhttp3.CertificatePinner", "javax.net.ssl.X509TrustManager"];

/** Presence-only check; must run inside Java.perform. Never installs a hook -- purely a cross-reference note. */
function detectJavaTlsPathCoverage() {
    const found = JAVA_TLS_MARKER_CLASSES.filter((className) => {
        try {
            Java.use(className);
            return true;
        } catch (e) {
            return false;
        }
    });
    if (found.length === 0) return;

    event(MODULE_NAME, "java_tls_path_detected", {
        classes_found: found,
        note:
            "tls_inspector's Java hooks (TrustManager/OkHttp/WebView) already cover this " +
            "path for any platform-channel networking this app may also use alongside dart:io.",
    });
}

// --------------------------------------------------------------------
// Native TLS stack identification
// --------------------------------------------------------------------

// Exported names that indicate a module carries its own OpenSSL/BoringSSL
// rather than merely linking against the system's. Presence is checked
// per-module (not process-wide) so the result reflects exactly what the
// discovered Flutter engine module exports, not whatever other TLS
// library happens to also be loaded in the process.
const TLS_SYMBOL_CANDIDATES = [
    "SSL_CTX_new",
    "SSL_CTX_set_verify",
    "SSL_CTX_set_custom_verify",
    "SSL_set_custom_verify",
    "SSL_get_verify_result",
    "X509_verify_cert",
];

/**
 * Best-effort library version string. BoringSSL deliberately does not
 * export a friendly version banner the way classic OpenSSL does, so
 * absence here is expected and not itself evidence of anything -- this
 * is purely a nice-to-have when the bundled library happens to be a
 * build of OpenSSL rather than BoringSSL.
 */
function readLibraryVersionString(moduleName) {
    for (const symbol of ["OpenSSL_version", "SSLeay_version"]) {
        let address;
        try {
            address = Module.findExportByName(moduleName, symbol);
        } catch (e) {
            continue;
        }
        if (address === null || address === undefined) continue;
        try {
            const fn = new NativeFunction(address, "pointer", ["int"]);
            const version = readCString(fn(0)); // 0 == OPENSSL_VERSION / SSLEAY_VERSION
            if (version) return version;
        } catch (e) {
            // best-effort only
        }
    }
    return null;
}

/**
 * Probes each discovered engine module for the TLS symbol candidates and
 * reports what's actually present. Returns only the modules where at
 * least one symbol was found -- those are the ones worth handing to the
 * bypass strategies below; a module with none of these exports isn't a
 * TLS implementation, whatever else it might be.
 */
function identifyNativeTlsStack(engineModules) {
    const modulesWithTls = [];
    for (const mod of engineModules) {
        const symbolsFound = TLS_SYMBOL_CANDIDATES.filter((symbol) => {
            try {
                return Module.findExportByName(mod.name, symbol) !== null;
            } catch (e) {
                return false;
            }
        });
        if (symbolsFound.length === 0) continue;

        event(MODULE_NAME, "native_tls_library_detected", {
            module: mod.name,
            symbols_found: symbolsFound,
            library_version: readLibraryVersionString(mod.name),
        });
        modulesWithTls.push(mod);
    }
    return modulesWithTls;
}

// --------------------------------------------------------------------
// Bypass strategies
// --------------------------------------------------------------------

/**
 * Extension point for Flutter-specific TLS bypass techniques. Each entry
 * is `{ name, description, apply(moduleNames) }`, where `apply` performs
 * the actual hook installation and returns an array of
 * `{ symbol, installed, moduleName? }` descriptors (the same shape
 * tls_inspector's installNativeTlsHooksForModules returns) so the caller
 * can report setup diagnostics uniformly regardless of which strategy
 * produced them. A future strategy (e.g. one targeting a different
 * native TLS implementation, or an additional native choke point) can be
 * added here without changing how it's invoked or reported.
 */
const TLS_BYPASS_STRATEGIES = [
    {
        name: "native_boringssl_custom_verify",
        description:
            "Neutralizes verification performed through the engine's own statically-linked " +
            "OpenSSL/BoringSSL, by reusing tls_inspector's native hooks scoped to the " +
            "discovered engine module(s).",
        apply(moduleNames) {
            return installNativeTlsHooksForModules(moduleNames);
        },
    },
];

function applyBypassStrategies(moduleNames) {
    for (const strategy of TLS_BYPASS_STRATEGIES) {
        try {
            const results = strategy.apply(moduleNames);
            for (const result of results) {
                if (result.installed) {
                    event(MODULE_NAME, "hook_installed", {
                        strategy: strategy.name,
                        symbol: result.symbol,
                        module: result.moduleName,
                    });
                } else {
                    event(MODULE_NAME, "hook_installation_failed", {
                        strategy: strategy.name,
                        symbol: result.symbol,
                    });
                }
            }
        } catch (e) {
            log(MODULE_NAME, "error", `Bypass strategy '${strategy.name}' threw: ${e.stack || e}`);
        }
    }
}

// --------------------------------------------------------------------
// Entry point (called by agents/loader.js)
// --------------------------------------------------------------------

export function init(config = {}) {
    bypassEnabled = Boolean(config.bypass);
    const extraModuleNames = Array.isArray(config.extra_native_modules)
        ? config.extra_native_modules.map(String)
        : [];

    let javaMarkers = [];
    if (isAndroid()) {
        Java.perform(() => {
            javaMarkers = detectFlutterJavaMarkers();
        });
    }

    const engineModules = discoverEngineModules(extraModuleNames);

    if (javaMarkers.length === 0 && engineModules.length === 0) {
        log(MODULE_NAME, "info", "No Flutter runtime detected; flutter_tls installed no hooks");
        return;
    }

    event(MODULE_NAME, "flutter_engine_detected", {
        java_markers: javaMarkers,
        native_modules: engineModules.map((mod) => ({
            name: mod.name,
            base: mod.base.toString(),
            size: mod.size,
            path: mod.path,
        })),
    });

    if (isAndroid()) {
        Java.perform(() => {
            detectJavaTlsPathCoverage();
        });
    }

    if (engineModules.length === 0) {
        event(MODULE_NAME, "fallback_path_selected", {
            reason: "no_native_engine_module_found",
            detail:
                "Flutter was detected via Java markers but no matching native module " +
                "(libflutter.so/libapp.so, or the iOS Flutter/App frameworks) could be " +
                "located; native TLS identification and hooking were skipped.",
        });
        log(MODULE_NAME, "info", "flutter_tls hooks installed", { bypass: bypassEnabled, native_modules_found: 0 });
        return;
    }

    inspectDartRuntime(engineModules);
    const modulesWithTls = identifyNativeTlsStack(engineModules);

    if (modulesWithTls.length === 0) {
        event(MODULE_NAME, "fallback_path_selected", {
            reason: "no_recognizable_tls_symbols",
            detail:
                "No known OpenSSL/BoringSSL export names were found in any discovered " +
                "engine module (possibly a stripped build). tls_inspector's own " +
                "process-wide native hooks may still cover this app if it also loads a " +
                "separate system TLS library.",
        });
    } else {
        applyBypassStrategies(modulesWithTls.map((mod) => mod.name));
    }

    log(MODULE_NAME, "info", "flutter_tls hooks installed", {
        bypass: bypassEnabled,
        native_modules_found: engineModules.length,
        tls_capable_modules: modulesWithTls.length,
    });
}
