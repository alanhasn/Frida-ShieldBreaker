// Native Android detector. Evidence-only -- installs no hooks.
//
// "Native Android" is defined by exclusion: an Android runtime with none
// of the cross-platform frameworks this subsystem otherwise detects.
// This is the one detector with any awareness of its siblings -- by
// convention, a new framework detector added to this subsystem should
// add its single most distinctive marker class to the list below too,
// so this stays an accurate negative signal as coverage grows.

import { isAndroid } from "../common/native_utils.js";
import { scoreEvidence, javaClassPresent } from "./scoring.js";

const CROSS_PLATFORM_EXCLUSION_MARKERS = [
    "io.flutter.embedding.engine.FlutterEngine",
    "com.facebook.react.bridge.ReactContext",
    "com.unity3d.player.UnityPlayer",
    "mono.android.Runtime",
    "org.apache.cordova.CordovaActivity",
    "com.getcapacitor.Bridge",
];

export function detect() {
    if (!isAndroid()) {
        return { framework: "native_android", confidence: 0, evidence: [] };
    }

    let foundExclusions = [];
    Java.perform(() => {
        foundExclusions = CROSS_PLATFORM_EXCLUSION_MARKERS.filter(javaClassPresent);
    });

    const { confidence, evidence } = scoreEvidence([
        { present: true, weight: 85, label: "Android runtime confirmed" },
        ...foundExclusions.map((className) => ({
            present: true,
            weight: -20,
            label: `cross-platform framework marker present, reducing confidence: ${className}`,
        })),
    ]);

    return { framework: "native_android", confidence, evidence };
}
