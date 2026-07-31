// Diagnostic recon module -- NOT a permanent bypass, a one-time
// investigative tool for when known detection vectors (fs_monitor's
// path/PackageManager checks, etc.) have all been confirmed bypassed
// yet the app still reacts to root/tamper detection. Guessing at
// individual APIs one at a time doesn't scale once a commercial RASP
// SDK is involved -- this instead makes the app tell us what fired:
//
//   1. Enumerates loaded classes matching common root/tamper/RASP-SDK
//      naming patterns and reports the list -- often reveals which SDK
//      is in play by name alone (e.g. a class under a vendor's package).
//   2. Hooks generic "reaction points" many such SDKs funnel into once
//      they've decided to react to a positive detection (show a block
//      dialog, finish the activity, kill the process) and captures a
//      Java stack trace at the moment each fires, so the exact call
//      chain leading to the block screen is visible.
//
// Expect noisy output: Dialog.show()/Activity.finish() fire for
// completely unrelated, legitimate UI too. Read for the frame near the
// moment the block screen actually appears, then hand the offending
// class/method to fs_monitor (or a new hook) for an actual bypass.

import { log, event } from "../common/rpc.js";
import { isAndroid } from "../common/native_utils.js";

const MODULE_NAME = "recon";

let bypassEnabled = false;

// Classes to fully trace once their presence is confirmed (e.g. via
// enumerateSuspiciousClasses() below) -- rather than guessing which
// specific method of a multi-method detection library the app actually
// calls, every declared method gets hooked and logged.
const KNOWN_LIBRARY_CLASSES_TO_TRACE = [
    "com.scottyab.rootbeer.RootBeer",
    "com.scottyab.rootbeer.RootBeerNative",
];

const SUSPICIOUS_CLASS_NAME_MARKERS = [
    "root", "magisk", "tamper", "integrity", "rasp", "shield",
    "frida", "xposed", "antidebug", "anti_debug", "security",
    "safetynet", "playintegrity", "jailbreak", "hook",
];

// AOSP/language-runtime package prefixes -- excluded from the keyword
// scan below. Matches here (android.security.* is the KeyStore/Keymaster
// API, android.view.ViewRootImpl is UI-tree plumbing, org.apache.xml.*
// is XML parsing internals, none of it detection code) are essentially
// always framework noise that drowns out the handful of classes that
// actually matter.
const FRAMEWORK_PACKAGE_PREFIXES = [
    "android.", "androidx.", "com.android.", "java.", "javax.",
    "libcore.", "dalvik.", "org.apache.", "org.json.", "org.xml.",
    "org.w3c.", "sun.", "kotlin.", "kotlinx.", "com.google.android.",
];

function isFrameworkClass(className) {
    return FRAMEWORK_PACKAGE_PREFIXES.some((prefix) => className.startsWith(prefix));
}

// Package prefixes for widely-used commercial mobile RASP/anti-tamper
// SDKs. Checked directly rather than by generic keyword -- a much more
// precise signal, since a hit here names the actual product in play.
const KNOWN_RASP_SDK_PREFIXES = [
    "com.talsec.", "io.talsec.",                       // Talsec freeRASP
    "io.zimperium.", "com.zimperium.",                  // Zimperium zDefend/zIAP
    "com.promon.", "no.promon.",                        // Promon SHIELD
    "com.guardsquare.", "com.dexguard.",                 // GuardSquare DexGuard RASP
    "com.appdome.",                                      // Appdome
    "com.arxan.", "com.digital.ai.", "com.digitalai.",   // Arxan / Digital.ai
    "com.oneupsecurity.",
    "com.trustlook.",
    "com.avast.", "io.avast.",
    "com.ensurity.",
    "com.vkey.",
];

// If MainActivity is (near enough) the *only* class under the app's own
// package, its real logic likely isn't Java at all -- these are the
// tell-tale loaded-class prefixes for the cross-platform frameworks that
// would explain that, and where root/jailbreak detection would then run
// in Dart/JS/IL instead of anything a Java-level Frida hook can see.
const CROSS_PLATFORM_FRAMEWORK_MARKERS = [
    { name: "Flutter", prefixes: ["io.flutter."] },
    { name: "React Native", prefixes: ["com.facebook.react.", "com.facebook.hermes.", "com.facebook.jni.", "com.facebook.soloader."] },
    { name: "Cordova", prefixes: ["org.apache.cordova."] },
    { name: "Capacitor", prefixes: ["com.getcapacitor."] },
    { name: "Unity", prefixes: ["com.unity3d."] },
];

const REACTION_POINTS = [
    { className: "android.app.Dialog", methodName: "show", label: "Dialog.show (covers AlertDialog + subclasses)" },
    { className: "android.app.Activity", methodName: "finish", label: "Activity.finish" },
    { className: "java.lang.System", methodName: "exit", label: "System.exit" },
    { className: "android.os.Process", methodName: "killProcess", label: "Process.killProcess" },
];

function currentStackTrace(maxFrames = 15) {
    try {
        const Thread = Java.use("java.lang.Thread");
        const frames = Thread.currentThread().getStackTrace();
        const lines = [];
        for (let i = 0; i < frames.length && lines.length < maxFrames; i++) {
            lines.push(frames[i].toString());
        }
        return lines;
    } catch (e) {
        return [];
    }
}

function getOwnPackageName() {
    try {
        const app = Java.use("android.app.ActivityThread").currentApplication();
        return app ? app.getPackageName() : null;
    } catch (e) {
        return null;
    }
}

/**
 * Four-tier scan, most-precise first:
 *   1. Classes under the app's own package -- this is where custom or
 *      even obfuscated detection code actually lives, and it's a small
 *      enough set that nothing drowns it out. If this stays tiny (e.g.
 *      just MainActivity) even once the app is fully running, the real
 *      logic likely isn't Java at all -- see tier 2.
 *   2. Cross-platform framework markers (Flutter/React Native/Cordova/
 *      Capacitor/Unity) -- answers that directly: if one of these is
 *      loaded, root/jailbreak detection is probably running in Dart/JS/
 *      IL, invisible to every Java hook this framework has written.
 *   3. Known commercial RASP SDK package prefixes -- a hit here names
 *      the actual product in play directly, no guessing required.
 *   4. Generic keyword matches, with AOSP/runtime packages excluded --
 *      catches anything the first three tiers miss, at the cost of some
 *      remaining noise from third-party libraries that happen to use
 *      words like "security" for unrelated reasons.
 */
function enumerateSuspiciousClasses() {
    const ownPackage = getOwnPackageName();
    const ownClasses = [];
    const frameworkHits = new Map(); // framework name -> example class names
    const raspMatches = [];
    const keywordMatches = [];

    try {
        Java.enumerateLoadedClasses({
            onMatch(className) {
                if (ownPackage && className.startsWith(`${ownPackage}.`)) {
                    ownClasses.push(className);
                    return;
                }
                for (const { name, prefixes } of CROSS_PLATFORM_FRAMEWORK_MARKERS) {
                    if (prefixes.some((prefix) => className.startsWith(prefix))) {
                        const examples = frameworkHits.get(name) ?? [];
                        if (examples.length < 5) examples.push(className);
                        frameworkHits.set(name, examples);
                        return;
                    }
                }
                if (KNOWN_RASP_SDK_PREFIXES.some((prefix) => className.startsWith(prefix))) {
                    raspMatches.push(className);
                    return;
                }
                if (isFrameworkClass(className)) return;
                const lower = className.toLowerCase();
                if (SUSPICIOUS_CLASS_NAME_MARKERS.some((marker) => lower.includes(marker))) {
                    keywordMatches.push(className);
                }
            },
            onComplete() {
                const frameworksDetected = Object.fromEntries(frameworkHits);
                event(MODULE_NAME, "suspicious_classes_found", {
                    own_package: ownPackage,
                    own_classes_count: ownClasses.length,
                    own_classes: ownClasses,
                    cross_platform_frameworks_detected: frameworksDetected,
                    known_rasp_sdk_matches: raspMatches,
                    keyword_matches_count: keywordMatches.length,
                    keyword_matches: keywordMatches.slice(0, 100),
                });
                const frameworkNames = [...frameworkHits.keys()];
                log(
                    MODULE_NAME, "info",
                    `Recon: ${ownClasses.length} class(es) under own package (${ownPackage}), ` +
                    `cross-platform framework(s): ${frameworkNames.length ? frameworkNames.join(", ") : "none detected"}, ` +
                    `${raspMatches.length} known-RASP-SDK match(es), ${keywordMatches.length} generic keyword match(es) (framework excluded)`
                );
                if (ownClasses.length <= 2 && frameworkNames.length === 0) {
                    log(
                        MODULE_NAME, "warning",
                        "Own package has almost no classes and no cross-platform framework was detected at this point in startup -- " +
                        "if detection still isn't found, consider re-running after more of the app has loaded, or that native (non-JVM) " +
                        "code loaded via System.loadLibrary() may be doing the check outside anything Java-visible."
                    );
                }
            },
        });
    } catch (e) {
        log(MODULE_NAME, "error", `Class enumeration failed: ${e.stack || e}`);
    }
}

function hookReactionPoint(className, methodName, label) {
    try {
        const Klass = Java.use(className);
        Klass[methodName].implementation = function (...args) {
            event(MODULE_NAME, "reaction_point_hit", {
                label,
                class: className,
                method: methodName,
                stack: currentStackTrace(),
            });
            return this[methodName](...args);
        };
        log(MODULE_NAME, "debug", `Hooked reaction point: ${label}`);
    } catch (e) {
        log(MODULE_NAME, "debug", `Reaction point not present: ${label} (${e.message})`);
    }
}

function installReactionPointHooks() {
    for (const { className, methodName, label } of REACTION_POINTS) {
        hookReactionPoint(className, methodName, label);
    }
}

function safeStringify(value) {
    if (value === null || value === undefined) return String(value);
    if (typeof value === "boolean" || typeof value === "number" || typeof value === "string") return value;
    try {
        return value.toString();
    } catch (e) {
        return "<unstringifiable>";
    }
}

// Every class this session has already installed a tracer on -- de-dupes
// repeat calls and stops the caller-auto-discovery cascade below from
// re-hooking (or infinitely recursing into) the same class.
const tracedClassNames = new Set();

// Caller auto-discovery naturally self-limits once it reaches AOSP/
// framework plumbing (Handler/Looper/etc., excluded via isFrameworkClass),
// but this caps it regardless as a hard safety net against any
// unexpectedly deep or noisy call chain.
const MAX_AUTO_TRACE_DEPTH = 4;

function parseClassNameFromStackFrame(frame) {
    // e.g. "com.scottyab.rootbeer.RootBeerNative.checkForRoot(Native Method)"
    // -> "com.scottyab.rootbeer.RootBeerNative"
    const parenIdx = frame.indexOf("(");
    const beforeParen = parenIdx >= 0 ? frame.slice(0, parenIdx) : frame;
    const lastDot = beforeParen.lastIndexOf(".");
    return lastDot >= 0 ? beforeParen.slice(0, lastDot) : beforeParen;
}

/** Finds whoever called `tracedClassName` by locating it in its own captured stack and taking the next frame up. */
function findCallerClassName(stackFrames, tracedClassName) {
    for (let i = 0; i < stackFrames.length - 1; i++) {
        if (parseClassNameFromStackFrame(stackFrames[i]) === tracedClassName) {
            return parseClassNameFromStackFrame(stackFrames[i + 1]);
        }
    }
    return null;
}

const hookedFlutterResultClasses = new Set();
const describedClassShapes = new Set();

/**
 * Reads a field's value via java.lang.reflect.Field rather than Frida's
 * `.fieldName.value` convenience sugar. That sugar resolves a single JS
 * property name against a class that may have *both* a field and a
 * method sharing that name -- common once an obfuscator (e.g. R8) has
 * squashed every member down to single letters -- and can silently
 * resolve to the method wrapper (which has no `.value`, hence
 * `undefined`) instead of the field. Reflection's Field/Method
 * namespaces are separate, so this can't repeat that failure mode.
 * Returns `undefined` (never throws) if the field doesn't exist, so
 * callers can distinguish "not present" from a real value including
 * Java `null`.
 */
function readFieldViaReflection(instance, fieldName) {
    try {
        const field = instance.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);
        const rawValue = field.get(instance);
        if (rawValue === null || rawValue === undefined) return rawValue;

        // Field.get() is declared to return Object, so Frida hands back a
        // generic, untyped wrapper regardless of the field's real
        // declared type -- its own toString() just prints a placeholder
        // like "<instance: java.lang.Object, $className: ...>" instead
        // of delegating to the real type's toString(). Re-casting to the
        // field's actual declared type (read off the same Field object)
        // makes Frida treat it correctly; for a String field this gets us
        // the real text instead of that placeholder.
        try {
            const fieldTypeName = field.getType().getName();
            const casted = Java.cast(rawValue, Java.use(fieldTypeName));
            return fieldTypeName === "java.lang.String" ? casted.toString() : casted;
        } catch (e) {
            return rawValue; // best-effort -- return the untyped wrapper rather than fail
        }
    } catch (e) {
        return undefined;
    }
}

/**
 * `value.getClass()` throwing is ambiguous by itself -- it means either
 * "value is null/undefined" (expected, not evidence of anything) or
 * "value is a real object but something else went wrong" (worth seeing),
 * or "this was never a Java object wrapper at all" (e.g. `getClass is
 * not a function`) -- e.g. a raw NativePointer, a JS primitive, or a
 * callback Frida represented some other way. `jsType` disambiguates
 * that last case directly instead of just recording that the accessor
 * attempt failed.
 */
function describeArg(value) {
    if (value === null || value === undefined) return { className: null, isNull: true, jsType: typeof value };
    try {
        return { className: value.getClass().getName(), isNull: false, jsType: typeof value };
    } catch (e) {
        return { className: `<error: ${e.message}>`, isNull: false, jsType: typeof value };
    }
}

/**
 * Reflection dump of a class's own declared fields + methods, reported
 * once per class name -- for when a mystery object (like an argument
 * that turned out not to be the Flutter type we assumed) needs its
 * actual shape inspected directly instead of guessing accessor names.
 */
function describeClassShapeOnce(className) {
    if (!className || describedClassShapes.has(className)) return;
    describedClassShapes.add(className);
    try {
        const Klass = Java.use(className);
        const fields = Klass.class.getDeclaredFields().map((f) => `${f.getType().getName()} ${f.getName()}`);
        const methodNames = [...new Set(Klass.class.getDeclaredMethods().map((m) => m.getName()))];
        event(MODULE_NAME, "unknown_class_shape", { class: className, fields, methods: methodNames });
        log(MODULE_NAME, "info", `Described shape of ${className}: ${fields.length} field(s), ${methodNames.length} method(s)`);
    } catch (e) {
        log(MODULE_NAME, "debug", `Failed to describe class shape for ${className}: ${e.stack || e}`);
    }
}

/**
 * Flutter's MethodChannel.MethodCallHandler.onMethodCall(MethodCall, Result)
 * is a semantically special shape: args[0] names which channel method was
 * actually invoked, args[1] is how the answer gets sent back to Dart.
 * Generic tracing only shows toString() of these two objects, which isn't
 * useful -- this extracts the real invoked method name directly via
 * reflection, and the first time it sees a given Result implementation,
 * auto-discovers and hooks its success()/error()/notImplemented() so the
 * exact value crossing the Java/Dart platform-channel boundary is visible.
 * A method literally named "onMethodCall" is not proof it's actually
 * Flutter's interface -- some apps have their own, unrelated method of
 * the same name -- so if the argument turns out not to be Flutter's real
 * MethodCall/Result, the discovered real class gets its shape dumped via
 * describeClassShapeOnce() instead of silently producing nulls.
 */
function tryHookFlutterMethodCallHandler(Klass, className, methodName) {
    if (methodName !== "onMethodCall") return false;
    try {
        const overloads = Klass[methodName].overloads;
        const twoArgOverloads = overloads.filter((ov) => ov.argumentTypes.length === 2);
        if (twoArgOverloads.length === 0) return false;

        // R8 can generate a synthetic bridge method for an interface
        // implementation -- Object,Object args that just cast and delegate
        // to the real typed one. Prefer the overload actually typed as
        // MethodCall; if that's not found (and only then), fall back to
        // whatever 2-arg overload exists, but log every overload's real
        // argument types so a bridge-method mismatch is directly visible
        // in evidence rather than silently producing null fields again.
        const typed = twoArgOverloads.find(
            (ov) => ov.argumentTypes[0].className === "io.flutter.plugin.common.MethodCall"
        );
        const target = typed || twoArgOverloads[0];
        if (!typed) {
            log(
                MODULE_NAME, "debug",
                `${className}.onMethodCall: no overload typed as MethodCall; ` +
                `2-arg overloads found: ${twoArgOverloads.map((ov) => ov.argumentTypes.map((t) => t.className).join(",")).join(" | ")}`
            );
        }

        target.implementation = function (call, result) {
            const callInfo = describeArg(call);
            const resultInfo = describeArg(result);

            // "method" is Flutter's real field name on MethodCall. Some
            // obfuscated builds expose an equivalent object under a
            // different concrete type where the same value lands on a
            // short, generated field name instead -- "a" is a common
            // case in R8-minified output, so it's tried next. Read via
            // reflection either way, not Frida's `.fieldName.value`
            // sugar: a class can have both a field and a method sharing
            // a name (common once an obfuscator has squashed everything
            // down to single letters), and that sugar can silently
            // resolve to the method wrapper -- which has no `.value`, so
            // it produces `undefined` instead of throwing. Reflection's
            // Field/Method namespaces don't collide, so this can't
            // repeat that failure mode.
            let invokedMethod = null;
            let invokedMethodField = null;
            for (const fieldName of ["method", "a"]) {
                const value = readFieldViaReflection(call, fieldName);
                if (value !== undefined) {
                    invokedMethod = value;
                    invokedMethodField = fieldName;
                    break;
                }
            }

            event(MODULE_NAME, "flutter_method_channel_call", {
                handler_class: className,
                overload_was_typed: Boolean(typed),
                call_class: callInfo.className,
                call_is_null: callInfo.isNull,
                call_js_type: callInfo.jsType,
                result_class: resultInfo.className,
                result_is_null: resultInfo.isNull,
                result_js_type: resultInfo.jsType,
                invoked_method: invokedMethod,
                invoked_method_field: invokedMethodField,
            });

            // Placeholder error strings from describeArg() aren't real
            // class names -- don't feed them to Java.use().
            const realClassName = (name) => (typeof name === "string" && !name.startsWith("<error:") ? name : null);

            describeClassShapeOnce(realClassName(callInfo.className));
            describeClassShapeOnce(realClassName(resultInfo.className));

            const resultClass = realClassName(resultInfo.className);
            if (resultClass && !resultInfo.isNull) hookFlutterResultReplyOnce(resultClass);

            return this.onMethodCall(call, result);
        };
        return true;
    } catch (e) {
        return false;
    }
}

/** Hooks success()/error()/notImplemented() on a discovered concrete MethodChannel.Result implementation, exactly once. */
function hookFlutterResultReplyOnce(resultClassName) {
    if (hookedFlutterResultClasses.has(resultClassName)) return;
    hookedFlutterResultClasses.add(resultClassName);

    try {
        const ResultClass = Java.use(resultClassName);
        ["success", "error", "notImplemented"].forEach((methodName) => {
            try {
                ResultClass[methodName].overloads.forEach((overload) => {
                    overload.implementation = function (...args) {
                        event(MODULE_NAME, "flutter_method_channel_reply", {
                            result_class: resultClassName,
                            method: methodName,
                            args: args.map(safeStringify),
                        });
                        return this[methodName](...args);
                    };
                });
            } catch (e) {
                // This concrete Result impl may not exposed all three -- skip.
            }
        });
        log(MODULE_NAME, "info", `Hooked Flutter MethodChannel.Result reply methods on ${resultClassName}`);
    } catch (e) {
        log(MODULE_NAME, "error", `Failed to hook discovered Result class ${resultClassName}: ${e.stack || e}`);
    }
}

/**
 * Generic "trace (and, when bypass is enabled, neutralize) every method
 * on a known class" -- for when a library's presence is confirmed (e.g.
 * RootBeer/RootBeerNative showing up in enumerateSuspiciousClasses())
 * but it's unclear which of its many methods the app actually calls.
 * Guessing individual method names one at a time doesn't scale for a
 * library with a dozen-plus leaf checks; this hooks everything the
 * class declares, logs every call with its real result and JS type
 * (RootBeerNative.checkForRoot returns `int`, not `boolean` -- a prior
 * version of this bypass compared `result === true`, which can never
 * match a number; fixed to a truthy check), and auto-discovers +
 * recursively traces whoever called it, so the actual caller (e.g. a
 * Flutter plugin's obfuscated glue class) doesn't have to be hardcoded
 * per app. May install a second `.implementation` over a hook
 * fs_monitor already set on the same method (e.g. RootBeerNative.
 * checkForRoot) when both modules run together -- harmless, since this
 * one is a strict superset (same call-through + bypass-on-truthy logic).
 */
function traceAndNeutralizeClass(className, depth = 0) {
    if (tracedClassNames.has(className)) return;
    tracedClassNames.add(className);

    let Klass;
    try {
        Klass = Java.use(className);
    } catch (e) {
        return; // class not present in this app
    }

    let methodNames;
    try {
        methodNames = [...new Set(Klass.class.getDeclaredMethods().map((m) => m.getName()))];
    } catch (e) {
        log(MODULE_NAME, "error", `Failed to enumerate methods of ${className}: ${e.stack || e}`);
        return;
    }

    let hookedCount = 0;
    for (const methodName of methodNames) {
        if (tryHookFlutterMethodCallHandler(Klass, className, methodName)) {
            hookedCount += 1;
            continue;
        }
        try {
            Klass[methodName].overloads.forEach((overload) => {
                overload.implementation = function (...args) {
                    const result = this[methodName](...args);
                    const bypassed = bypassEnabled && Boolean(result);
                    const callerStack = currentStackTrace(8);
                    event(MODULE_NAME, "library_method_trace", {
                        class: className,
                        method: methodName,
                        args: args.map(safeStringify),
                        result: safeStringify(result),
                        result_type: typeof result,
                        bypassed,
                        caller_stack: callerStack,
                    });

                    if (depth < MAX_AUTO_TRACE_DEPTH) {
                        const callerClass = findCallerClassName(callerStack, className);
                        if (callerClass && !isFrameworkClass(callerClass) && !tracedClassNames.has(callerClass)) {
                            log(MODULE_NAME, "info", `Auto-discovered caller of ${className}.${methodName}: ${callerClass} -- tracing it too`);
                            traceAndNeutralizeClass(callerClass, depth + 1);
                        }
                    }

                    // Frida's Java bridge enforces that the returned value is
                    // compatible with the method's *declared* return type --
                    // RootBeerNative.checkForRoot()/setLogDebugMessages() are
                    // both declared `native int`, not `boolean` (confirmed
                    // against RootBeer's real source), so unconditionally
                    // returning the JS boolean `false` here throws
                    // "expected return value compatible with int" and can
                    // corrupt whatever call chain was mid-flight when it did.
                    if (!bypassed) return result;
                    return typeof result === "number" ? 0 : false;
                };
            });
            hookedCount += 1;
        } catch (e) {
            // Some methods can't be hooked this way (private native
            // helpers with no resolvable overload, etc.) -- skip.
        }
    }
    log(MODULE_NAME, "info", `Traced ${hookedCount}/${methodNames.length} method(s) on ${className}`);
}

function traceKnownLibraries() {
    for (const className of KNOWN_LIBRARY_CLASSES_TO_TRACE) {
        traceAndNeutralizeClass(className);
    }
}

export function init(config = {}) {
    bypassEnabled = Boolean(config.bypass);

    if (!isAndroid()) {
        log(MODULE_NAME, "warning", "recon currently only implements Android hooks");
        return;
    }
    Java.perform(() => {
        enumerateSuspiciousClasses();
        installReactionPointHooks();
        traceKnownLibraries();
    });
    log(MODULE_NAME, "info", "recon hooks installed", { bypass: bypassEnabled });
}
