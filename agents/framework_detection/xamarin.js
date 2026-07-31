// Xamarin framework detector. Evidence-only -- installs no hooks.

import { findModules, isAndroid } from "../common/native_utils.js";
import { scoreEvidence, javaClassPresent } from "./scoring.js";

// libmonodroid/libmonosgen are the Mono runtime Xamarin.Android embeds;
// libxamarin-app is Xamarin's own glue library. "xamarin" is included as
// a bare substring candidate (findModules matches substrings) as a
// defensive fallback across build/naming variants, including iOS.
const NATIVE_MODULE_CANDIDATES = ["libmonodroid.so", "libmonosgen-2.0.so", "libxamarin-app.so", "xamarin"];

// mono.android.Runtime is Xamarin.Android's own bootstrap class and is
// weighted to cross the detection threshold alone -- see detector.js for
// why Java evidence is weighted more heavily than native evidence here.
const JAVA_MARKERS = [
    { className: "mono.android.Runtime", weight: 55 },
    { className: "mono.android.app.MonoApplication", weight: 15 },
    { className: "mono.MonoPackageManager", weight: 10 },
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
            label: `Xamarin/Mono native module loaded (${nativeModules.map((m) => m.name).join(", ")})`,
        },
        ...javaMarkersFound.map((marker) => ({
            present: true,
            weight: marker.weight,
            label: `${marker.className} present`,
        })),
    ]);

    return { framework: "xamarin", confidence, evidence };
}
