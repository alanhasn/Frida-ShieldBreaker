// Capacitor framework detector. Evidence-only -- installs no hooks.
//
// Like Cordova, Capacitor is a WebView shell with no distinctive native
// library of its own -- Java marker classes are the only reliable
// signal available.

import { isAndroid } from "../common/native_utils.js";
import { scoreEvidence, javaClassPresent } from "./scoring.js";

const JAVA_MARKERS = [
    { className: "com.getcapacitor.BridgeActivity", weight: 60 },
    { className: "com.getcapacitor.Bridge", weight: 20 },
];

export function detect() {
    let javaMarkersFound = [];
    if (isAndroid()) {
        Java.perform(() => {
            javaMarkersFound = JAVA_MARKERS.filter((marker) => javaClassPresent(marker.className));
        });
    }

    const { confidence, evidence } = scoreEvidence(
        javaMarkersFound.map((marker) => ({
            present: true,
            weight: marker.weight,
            label: `${marker.className} present`,
        }))
    );

    return { framework: "capacitor", confidence, evidence };
}
