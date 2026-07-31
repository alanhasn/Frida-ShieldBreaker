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
import { isAndroid, findModules, readCString } from "../common/native_utils.js";

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
// iOS framework binary names as Frida reports them once loaded.
const DEFAULT_ENGINE_MODULE_NAMES = ["libflutter.so", "libapp.so", "Flutter", "App"];

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
    const candidates = [...DEFAULT_ENGINE_MODULE_NAMES, ...extraModuleNames];
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

    log(MODULE_NAME, "info", "flutter_tls hooks installed", {
        bypass: bypassEnabled,
        native_modules_found: engineModules.length,
    });
}
