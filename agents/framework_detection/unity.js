// Unity framework detector. Evidence-only -- installs no hooks.

import { findModules, isAndroid } from "../common/native_utils.js";
import { scoreEvidence, javaClassPresent } from "./scoring.js";

// libunity.so/UnityFramework is the engine itself; il2cpp and mono are
// Unity's two alternative scripting backends -- a build has exactly one
// of them, never both, so which one is present doubles as evidence of
// which backend this build uses.
const CORE_MODULE_CANDIDATES = ["libunity.so", "UnityFramework"];
const IL2CPP_MODULE_CANDIDATES = ["libil2cpp.so"];
const MONO_MODULE_CANDIDATES = ["libmono.so", "libmonobdwgc-2.0.so"];

// UnityPlayer is present on virtually every Unity Android build and is
// weighted to cross the detection threshold alone -- see detector.js for
// why Java evidence is weighted more heavily than native evidence here.
const JAVA_MARKERS = [
    { className: "com.unity3d.player.UnityPlayer", weight: 55 },
    { className: "com.unity3d.player.UnityPlayerActivity", weight: 10 },
];

export function detect() {
    const coreModules = findModules(CORE_MODULE_CANDIDATES);
    const il2cppModules = findModules(IL2CPP_MODULE_CANDIDATES);
    const monoModules = findModules(MONO_MODULE_CANDIDATES);

    let javaMarkersFound = [];
    if (isAndroid()) {
        Java.perform(() => {
            javaMarkersFound = JAVA_MARKERS.filter((marker) => javaClassPresent(marker.className));
        });
    }

    const { confidence, evidence } = scoreEvidence([
        {
            present: coreModules.length > 0,
            weight: 40,
            label: `Unity core native module loaded (${coreModules.map((m) => m.name).join(", ")})`,
        },
        { present: il2cppModules.length > 0, weight: 15, label: "IL2CPP scripting backend detected (libil2cpp.so)" },
        { present: monoModules.length > 0, weight: 15, label: "Mono scripting backend detected" },
        ...javaMarkersFound.map((marker) => ({
            present: true,
            weight: marker.weight,
            label: `${marker.className} present`,
        })),
    ]);

    return { framework: "unity", confidence, evidence };
}
