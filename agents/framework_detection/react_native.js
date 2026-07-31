// React Native framework detector. Evidence-only -- installs no hooks.

import { findModules, isAndroid } from "../common/native_utils.js";
import { scoreEvidence, javaClassPresent } from "./scoring.js";

// libreactnativejni/libfbjni are the RN Android JNI bridge itself,
// present regardless of JS engine choice. libhermes/libjsc identify
// which JS engine backs the bridge (Hermes is the default since RN 0.70;
// JSC was the long-standing default before that and remains an option).
const NATIVE_MODULE_CANDIDATES = ["libreactnativejni.so", "libfbjni.so", "libhermes.so", "libjsc.so"];

// ReactContext is the core RN runtime object and is weighted to cross
// the detection threshold alone, for the same reason FlutterEngine is in
// flutter.js: Java evidence is available earlier than native-library
// evidence (see detector.js).
const JAVA_MARKERS = [
    { className: "com.facebook.react.bridge.ReactContext", weight: 55 },
    { className: "com.facebook.react.ReactActivity", weight: 15 },
    { className: "com.facebook.soloader.SoLoader", weight: 10 }, // used by other Meta tech too -- weaker signal alone
];

export function detect() {
    const nativeModules = findModules(NATIVE_MODULE_CANDIDATES);

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
            label: `React Native native module loaded (${nativeModules.map((m) => m.name).join(", ")})`,
        },
        ...javaMarkersFound.map((marker) => ({
            present: true,
            weight: marker.weight,
            label: `${marker.className} present`,
        })),
    ]);

    return { framework: "react_native", confidence, evidence };
}
