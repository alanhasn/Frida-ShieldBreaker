// Automatic framework detection engine.
//
// Identifies the target application's technology stack at runtime so
// the CLI's `--auto`/`--detect` flag can enable the relevant
// instrumentation modules instead of the user needing to know which
// ones apply in advance (see agents/loader.js's bootstrap() and
// main.py's --auto flag).
//
// A note on evidence timing: this runs once, synchronously, during the
// agent's bootstrap -- the same point every module's init() already
// runs from, and for the same reason (core/loader.py's spawn() leaves
// the process suspended specifically so hooks are installed before
// resume(), catching checks that fire early in the app's own startup).
// That timing has a consequence for detection: on Android, an app's
// classloader (and therefore its own Java classes, e.g. FlutterEngine or
// UnityPlayer) is typically already set up by this point, but its own
// native libraries (e.g. libflutter.so) are usually loaded later, via
// System.loadLibrary() calls that happen during Application/Activity
// initialization -- which hasn't run yet. Each detector below accounts
// for this by weighting its single most distinctive Java marker class
// heavily enough to cross the detection threshold on its own; native
// library evidence, when it happens to already be available (notably
// when attaching to an already-running process with --attach rather
// than spawning), only adds further confidence on top.
//
// Adding a new framework detector:
//   1. Create framework_detection/<name>.js exporting detect(), which
//      must return { framework, confidence (0-100), evidence: string[] }
//      and must not throw.
//   2. Import it below and add it to the DETECTORS array.
//   3. Add its module mapping to FRAMEWORK_MODULE_MAP.
//   4. If it's a distinct Android app type, add its primary marker class
//      to native_android.js's exclusion list.
// Nothing else in this file needs to change.

import { log, event } from "../common/rpc.js";
import { detect as detectFlutter } from "./flutter.js";
import { detect as detectReactNative } from "./react_native.js";
import { detect as detectUnity } from "./unity.js";
import { detect as detectXamarin } from "./xamarin.js";
import { detect as detectCordova } from "./cordova.js";
import { detect as detectCapacitor } from "./capacitor.js";
import { detect as detectNativeAndroid } from "./native_android.js";

const MODULE_NAME = "framework_detection";

const DETECTORS = [
    detectFlutter,
    detectReactNative,
    detectUnity,
    detectXamarin,
    detectCordova,
    detectCapacitor,
    detectNativeAndroid,
];

/**
 * Which modules (agents/loader.js MODULE_REGISTRY keys) to enable for
 * each detected framework. Deliberately data, not logic -- adjusting
 * which modules a framework pulls in, or adding a new framework's
 * mapping, doesn't require touching any detection code.
 */
const FRAMEWORK_MODULE_MAP = {
    flutter: ["flutter_tls", "tls", "recon", "fs"],
    react_native: ["tls", "recon", "fs"],
    unity: ["tls", "recon", "antidebug"],
    xamarin: ["tls", "recon", "fs"],
    cordova: ["tls", "recon", "fs"],
    capacitor: ["tls", "recon", "fs"],
    native_android: ["tls", "recon", "fs", "antidebug"],
};

// Fallback module set when no detector clears the threshold -- e.g. an
// unrecognized framework, or a plain native iOS app (no detector here
// specifically targets that). Mirrors the CLI's own pre-existing default
// module set so automatic selection never does *less* than manually
// running with no flags at all.
const FALLBACK_MODULES = ["fs", "tls", "antidebug"];

// A detector's score must reach this to count as "detected" for
// automatic module selection. Every detector above weights its single
// strongest, most distinctive marker to clear this on its own.
const CONFIDENCE_THRESHOLD = 50;

let cachedResult = null;

function runDetectors() {
    return DETECTORS.map((detectorFn) => {
        try {
            const result = detectorFn();
            return {
                framework: String(result.framework),
                confidence: Math.max(0, Math.min(100, Math.round(Number(result.confidence) || 0))),
                evidence: Array.isArray(result.evidence) ? result.evidence : [],
            };
        } catch (e) {
            log(MODULE_NAME, "error", `Detector threw: ${e.stack || e}`);
            return { framework: "unknown", confidence: 0, evidence: [] };
        }
    });
}

/**
 * Runs every registered detector exactly once per process and caches the
 * result -- framework composition doesn't change over a process's
 * lifetime, so repeated calls (e.g. from both module selection and a
 * future diagnostics command) never repeat the actual detection work.
 */
export function detectFrameworks() {
    if (cachedResult !== null) return cachedResult;

    event(MODULE_NAME, "framework_detection_started", {});

    const results = runDetectors();

    for (const result of results) {
        event(MODULE_NAME, "framework_confidence", {
            framework: result.framework,
            confidence: result.confidence,
        });
        if (result.evidence.length > 0) {
            event(MODULE_NAME, "framework_evidence", {
                framework: result.framework,
                evidence: result.evidence,
            });
        }
    }

    const detected = results
        .filter((r) => r.confidence >= CONFIDENCE_THRESHOLD)
        .sort((a, b) => b.confidence - a.confidence);

    for (const result of detected) {
        event(MODULE_NAME, "framework_detected", {
            framework: result.framework,
            confidence: result.confidence,
            evidence: result.evidence,
        });
    }

    cachedResult = { results, detected };

    event(MODULE_NAME, "framework_detection_finished", {
        detected: detected.map((r) => r.framework),
    });

    return cachedResult;
}

/**
 * Maps detected frameworks to the module list to auto-enable. When more
 * than one framework clears the threshold (e.g. a WebView shell embedding
 * a game view), their module lists are unioned rather than only the
 * top-scoring one used -- either framework's checks being relevant is a
 * reason to enable its modules, not a reason to exclude them.
 */
export function selectModulesForDetectedFrameworks() {
    const { detected } = detectFrameworks();

    const selected = new Set();
    for (const result of detected) {
        const modules = FRAMEWORK_MODULE_MAP[result.framework];
        if (!modules) continue;
        for (const name of modules) selected.add(name);
    }

    const enabledModules = selected.size > 0 ? [...selected] : [...FALLBACK_MODULES];

    event(MODULE_NAME, "automatic_modules_selected", {
        frameworks: detected.map((r) => r.framework),
        modules: enabledModules,
    });

    return enabledModules;
}
