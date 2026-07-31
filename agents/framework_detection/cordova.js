// Cordova framework detector. Evidence-only -- installs no hooks.
//
// Cordova has no distinctive native library of its own -- it's a WebView
// shell around the platform's own web engine, so Java marker classes are
// the only reliable signal available. Weighted higher than the
// cross-platform-engine detectors' single-marker weight since there's no
// native-module evidence to corroborate with here at all.

import { isAndroid } from "../common/native_utils.js";
import { scoreEvidence, javaClassPresent } from "./scoring.js";

const JAVA_MARKERS = [
    { className: "org.apache.cordova.CordovaActivity", weight: 60 },
    { className: "org.apache.cordova.CordovaWebView", weight: 20 },
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

    return { framework: "cordova", confidence, evidence };
}
