// Flutter framework detector. Evidence-only -- installs no hooks. See
// agents/flutter_tls/flutter_tls.js for actual Flutter TLS
// instrumentation, which performs its own independent detection so it
// remains usable even when this detection subsystem hasn't run (e.g.
// `--modules flutter_tls` without `--auto`).

import { findModules, isAndroid } from "../common/native_utils.js";
import { scoreEvidence, javaClassPresent } from "./scoring.js";

// Android: libflutter.so is the engine itself (Dart VM + BoringSSL);
// libapp.so is the compiled Dart AOT snapshot and may be absent in
// JIT/debug builds. iOS: Flutter/App are the equivalent framework binary
// names as Frida reports them once loaded.
const NATIVE_MODULE_CANDIDATES = ["libflutter.so", "libapp.so", "Flutter", "App"];

// FlutterEngine is weighted to cross the detection threshold alone: it's
// present as soon as the app's classloader is set up, which (on Android)
// is typically true even before resume() in spawn mode, well before
// libflutter.so has actually been dlopen'd -- see detector.js for the
// full explanation of why Java evidence and native evidence are not
// equally available depending on when detection runs.
const JAVA_MARKERS = [
    { className: "io.flutter.embedding.engine.FlutterEngine", weight: 55 },
    { className: "io.flutter.plugin.common.MethodChannel", weight: 15 },
    { className: "io.flutter.view.FlutterNativeView", weight: 10 }, // legacy pre-embedding-v2 entry point
];

export function detect() {
    const nativeModules = findModules(NATIVE_MODULE_CANDIDATES);

    let dartRuntimeFound = false;
    for (const mod of nativeModules) {
        try {
            if (Module.findExportByName(mod.name, "Dart_VersionString") !== null) {
                dartRuntimeFound = true;
                break;
            }
        } catch (e) {
            // module not queryable this way -- not evidence either way
        }
    }

    let javaMarkersFound = [];
    if (isAndroid()) {
        Java.perform(() => {
            javaMarkersFound = JAVA_MARKERS.filter((marker) => javaClassPresent(marker.className));
        });
    }

    const { confidence, evidence } = scoreEvidence([
        {
            present: nativeModules.length > 0,
            weight: 40,
            label: `native engine module loaded (${nativeModules.map((m) => m.name).join(", ")})`,
        },
        { present: dartRuntimeFound, weight: 15, label: "Dart runtime detected (Dart_VersionString export)" },
        ...javaMarkersFound.map((marker) => ({
            present: true,
            weight: marker.weight,
            label: `${marker.className} present`,
        })),
    ]);

    return { framework: "flutter", confidence, evidence };
}
