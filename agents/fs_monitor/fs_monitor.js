// Module 2: File System & Environment Monitoring.
//
// Traces file-check APIs (native libc, Android Java, iOS ObjC) that
// apps commonly use to look for root/jailbreak artifacts, and reports
// every suspicious-path check back to Python as a structured `event`
// -- including whether the checked path/command actually resolved,
// so an analyst can see both what the app looked for and what it saw.
//
// When config.bypass is set, every check that would have revealed a
// root/jailbreak artifact (exists === true) is flipped to report
// "not found" instead, so the app's own detection logic concludes the
// device is clean. Bypass is opt-in and off by default so this module
// is safe to run as pure observability if that's all an engagement needs.

import { log, event } from "../common/rpc.js";
import { attachSafe, resolveExport, isAndroid, isIOS, platformInfo } from "../common/native_utils.js";

const MODULE_NAME = "fs_monitor";
const ENOENT = 2; // same numeric value on Linux/Android (Bionic) and Darwin (iOS)

let bypassEnabled = false;

// Matched as case-insensitive substrings against every path/command we
// observe. Kept as one shared list so native, Java, and ObjC hooks all
// agree on what counts as "suspicious".
const DEFAULT_SUSPICIOUS_PATH_MARKERS = [
    // Android / generic root
    "/system/bin/su",
    "/system/xbin/su",
    "/sbin/su",
    "/su/bin/su",
    "/system/app/superuser.apk",
    "/system/app/supersu",
    "magisk",
    "com.topjohnwu.magisk",
    "/system/etc/init.d/",
    "busybox",
    "test-keys",
    // iOS jailbreak
    "/applications/cydia.app",
    "/library/mobilesubstrate/",
    "/bin/bash",
    "/usr/sbin/sshd",
    "/etc/apt",
    "/private/var/lib/apt",
    "/private/var/lib/cydia",
    "/private/var/tmp/cydia.log",
    "/applications/blackra1n.app",
    "/applications/sbsettings.app",
    "cydia",
    "substrate",
    // instrumentation artifacts (relevant to this framework's own OPSEC surface)
    "frida-server",
    "/usr/lib/frida",
];

const SU_EXEC_MARKERS = ["su", "which su", "busybox", "magisk"];

// Binaries commonly shelled out to for root/environment fingerprinting.
// When bypass is enabled, invocations of these never actually run --
// their argv is rewritten to a harmless `echo` before the real exec()/
// start() happens, so we never need to intercept or drain a Process's
// output streams (whose concrete class varies by Android version).
const SENSITIVE_EXEC_BINARIES = new Set(["getprop", "mount", "which", "id", "su"]);

// Values a clean, non-rooted device would report for the keys apps most
// commonly probe -- shared between the `getprop <key>` exec spoof below
// and any direct property-read hook added later.
const SPOOFED_PROPERTY_VALUES = {
    "ro.build.tags": "release-keys",
    "ro.debuggable": "0",
    "ro.secure": "1",
    "ro.build.type": "user",
    "ro.build.selinux": "enforcing",
    "ro.boot.verifiedbootstate": "green",
    "ro.boot.flash.locked": "1",
    "ro.boot.veritymode": "enforced",
};

let activeMarkers = DEFAULT_SUSPICIOUS_PATH_MARKERS;

function isSuspiciousPath(path) {
    if (typeof path !== "string" || path.length === 0) return false;
    const lower = path.toLowerCase();
    return activeMarkers.some((marker) => lower.includes(marker));
}

function reportPathCheck(source, api, path, extra = {}) {
    if (!isSuspiciousPath(path)) return;
    event(MODULE_NAME, "suspicious_path_check", { source, api, path, ...extra });
}

// --------------------------------------------------------------------
// Native (libc) hooks -- shared by Android (Bionic) and iOS (libSystem)
// --------------------------------------------------------------------

function readCString(pointer) {
    if (pointer === null || pointer === undefined || pointer.isNull()) return null;
    try {
        return pointer.readCString();
    } catch (e) {
        return null;
    }
}

function existsFromZeroRetval(retval) {
    return retval.toInt32() === 0;
}

function existsFromNonNegativeRetval(retval) {
    return retval.toInt32() >= 0;
}

function existsFromNonNullPointer(retval) {
    return !retval.isNull();
}

function bypassIntFailure(retval) {
    retval.replace(-1);
}

function bypassNullFailure(retval) {
    retval.replace(ptr(0));
}

// __errno (Bionic/Android) / __error (Darwin/iOS) / __errno_location (glibc,
// kept as a fallback) all return `int *` to the calling thread's errno slot.
// Resolved lazily -- most callers never touch bypass mode, so there's no
// reason to pay for this lookup at hook-install time.
let errnoAccessor; // undefined = not yet resolved, false = resolved-and-absent

function getErrnoAccessor() {
    if (errnoAccessor !== undefined) return errnoAccessor;
    const resolved = resolveExport([[null, "__errno"], [null, "__error"], [null, "__errno_location"]]);
    if (resolved === null) {
        log(MODULE_NAME, "debug", "No __errno/__error export found; bypass will skip errno spoofing");
        errnoAccessor = false;
        return errnoAccessor;
    }
    errnoAccessor = new NativeFunction(resolved.address, "pointer", []);
    return errnoAccessor;
}

function spoofErrno() {
    const accessor = getErrnoAccessor();
    if (!accessor) return;
    try {
        accessor().writeS32(ENOENT);
    } catch (e) {
        // best-effort only; never let errno spoofing take down the hook
    }
}

/**
 * Hooks a libc function whose Nth argument is a `const char *path`,
 * reporting only calls whose path matches a suspicious-path marker.
 * `classify(retval)` turns the raw return value into an "exists"
 * boolean using that function's own success convention; `bypassRetval`
 * (when bypass is enabled and the check found the artifact) rewrites
 * the return value to whatever that function uses to signal failure.
 */
function hookPathArgFn(candidates, apiName, { pathArgIndex = 0, classify = existsFromZeroRetval, bypassRetval = null } = {}) {
    const resolved = resolveExport(candidates);
    if (resolved === null) {
        log(MODULE_NAME, "debug", `${apiName}: no matching export found on this process`, { candidates });
        return;
    }

    attachSafe(MODULE_NAME, resolved.address, {
        onEnter(args) {
            this.path = readCString(args[pathArgIndex]);
            this.suspicious = isSuspiciousPath(this.path);
        },
        onLeave(retval) {
            if (!this.suspicious) return;
            const exists = classify(retval);
            const bypassed = bypassEnabled && exists && typeof bypassRetval === "function";
            reportPathCheck("native", apiName, this.path, {
                symbol: `${resolved.moduleName}!${resolved.symbolName}`,
                exists,
                bypassed,
            });
            if (bypassed) {
                bypassRetval(retval);
                spoofErrno();
            }
        },
    });
    log(MODULE_NAME, "debug", `Hooked ${apiName} -> ${resolved.moduleName}!${resolved.symbolName}`);
}

/**
 * readlink()/readlinkat() -- a symlink-based root check gap: apps
 * sometimes resolve e.g. /system/xbin/su via readlink rather than
 * open/access/stat. Trace-only for now (no bypassRetval) -- there's no
 * evidence yet this matters for any target, so it's not worth guessing
 * at a convincing fake symlink target to write back.
 */
function installReadlinkHooks() {
    const resolved = resolveExport([[null, "readlink"]]);
    if (resolved !== null) {
        attachSafe(MODULE_NAME, resolved.address, {
            onEnter(args) {
                this.path = readCString(args[0]);
                this.suspicious = isSuspiciousPath(this.path);
            },
            onLeave(retval) {
                if (!this.suspicious) return;
                reportPathCheck("native", "readlink", this.path, {
                    symbol: `${resolved.moduleName}!${resolved.symbolName}`,
                    exists: retval.toInt32() >= 0,
                    bypassed: false,
                });
            },
        });
        log(MODULE_NAME, "debug", `Hooked readlink -> ${resolved.moduleName}!${resolved.symbolName}`);
    } else {
        log(MODULE_NAME, "debug", "readlink: no matching export found");
    }

    const resolvedAt = resolveExport([[null, "readlinkat"]]);
    if (resolvedAt !== null) {
        attachSafe(MODULE_NAME, resolvedAt.address, {
            onEnter(args) {
                this.path = readCString(args[1]); // readlinkat(int dirfd, const char *pathname, ...)
                this.suspicious = isSuspiciousPath(this.path);
            },
            onLeave(retval) {
                if (!this.suspicious) return;
                reportPathCheck("native", "readlinkat", this.path, {
                    symbol: `${resolvedAt.moduleName}!${resolvedAt.symbolName}`,
                    exists: retval.toInt32() >= 0,
                    bypassed: false,
                });
            },
        });
        log(MODULE_NAME, "debug", `Hooked readlinkat -> ${resolvedAt.moduleName}!${resolvedAt.symbolName}`);
    } else {
        log(MODULE_NAME, "debug", "readlinkat: no matching export found");
    }
}

function installNativeHooks() {
    hookPathArgFn([[null, "open"]], "open", { classify: existsFromNonNegativeRetval, bypassRetval: bypassIntFailure });
    hookPathArgFn([[null, "openat"]], "openat", { pathArgIndex: 1, classify: existsFromNonNegativeRetval, bypassRetval: bypassIntFailure });
    hookPathArgFn([[null, "fopen"]], "fopen", { classify: existsFromNonNullPointer, bypassRetval: bypassNullFailure });
    hookPathArgFn([[null, "access"]], "access", { classify: existsFromZeroRetval, bypassRetval: bypassIntFailure });
    hookPathArgFn([[null, "faccessat"]], "faccessat", { pathArgIndex: 1, classify: existsFromZeroRetval, bypassRetval: bypassIntFailure });
    hookPathArgFn([[null, "stat"], [null, "stat64"]], "stat", { classify: existsFromZeroRetval, bypassRetval: bypassIntFailure });
    hookPathArgFn([[null, "lstat"], [null, "lstat64"]], "lstat", { classify: existsFromZeroRetval, bypassRetval: bypassIntFailure });
    hookPathArgFn([[null, "fstatat"], [null, "fstatat64"]], "fstatat", { pathArgIndex: 1, classify: existsFromZeroRetval, bypassRetval: bypassIntFailure });
    installReadlinkHooks();
}

// --------------------------------------------------------------------
// Android (Java) hooks
// --------------------------------------------------------------------

function hookJavaFileChecks() {
    try {
        const JavaFile = Java.use("java.io.File");

        JavaFile.exists.implementation = function () {
            const path = this.getAbsolutePath();
            const result = this.exists();
            const suspicious = isSuspiciousPath(path);
            const bypassed = bypassEnabled && suspicious && result;
            if (suspicious) {
                event(MODULE_NAME, "suspicious_path_check", {
                    source: "java",
                    api: "java.io.File.exists",
                    path,
                    exists: result,
                    bypassed,
                });
            }
            return bypassed ? false : result;
        };

        // Constructor overload File(String pathname) -- catches paths that
        // are constructed and used (e.g. fed to a FileInputStream) without
        // ever calling exists() on them.
        JavaFile.$init.overload("java.lang.String").implementation = function (pathname) {
            reportPathCheck("java", "java.io.File.<init>", pathname);
            return this.$init(pathname);
        };
    } catch (e) {
        log(MODULE_NAME, "error", `Failed to hook java.io.File: ${e.stack || e}`);
    }
}

function javaStringArrayToJs(arr) {
    if (arr === null) return [];
    const out = [];
    for (let i = 0; i < arr.length; i++) out.push(arr[i]);
    return out;
}

function javaListToJs(list) {
    if (list === null) return [];
    const out = [];
    const it = list.iterator();
    while (it.hasNext()) out.push(it.next().toString());
    return out;
}

function reportExecCall(api, argv, bypassed = false) {
    const joined = argv.join(" ").toLowerCase();
    const suCheck = SU_EXEC_MARKERS.some((marker) => joined.includes(marker));
    event(MODULE_NAME, "process_exec", { source: "java", api, argv, su_check: suCheck, bypassed });
}

function isSensitiveBinary(argv) {
    const bin = (argv[0] || "").toString().split("/").pop();
    return SENSITIVE_EXEC_BINARIES.has(bin);
}

/**
 * Rewrites a sensitive command's argv into a harmless `echo` that
 * produces the desired (safe or empty) output. `getprop <key>` gets a
 * plausible spoofed value for known root-indicator keys; a bare
 * `getprop` (full property dump) and everything else sensitive
 * (mount/which/id/su) just produce no output at all -- there's no
 * meaningful partial spoof for a full dump, and an app that can't find
 * what it's looking for behaves the same as one that got a clean answer.
 */
function buildSpoofedArgv(argv) {
    const bin = (argv[0] || "").toString().split("/").pop();

    if (bin === "getprop" && argv.length > 1) {
        const key = argv[1];
        const value = Object.prototype.hasOwnProperty.call(SPOOFED_PROPERTY_VALUES, key)
            ? SPOOFED_PROPERTY_VALUES[key]
            : "";
        return ["/system/bin/echo", value];
    }

    return ["/system/bin/echo", "-n", ""];
}

function hookJavaRuntimeExec() {
    try {
        const Runtime = Java.use("java.lang.Runtime");

        Runtime.exec.overload("java.lang.String").implementation = function (command) {
            // Runtime.exec(String) tokenizes on whitespace internally --
            // mirrored here only to identify the binary, not to build the
            // real argv (the original `command` string is still what's
            // passed through when we're not bypassing).
            const argv = command.split(/\s+/).filter((s) => s.length > 0);
            const bypassed = bypassEnabled && isSensitiveBinary(argv);
            reportExecCall("Runtime.exec(String)", argv, bypassed);
            if (bypassed) {
                return this.exec(buildSpoofedArgv(argv).join(" "));
            }
            return this.exec(command);
        };

        Runtime.exec.overload("[Ljava.lang.String;").implementation = function (cmdarray) {
            const argv = javaStringArrayToJs(cmdarray);
            const bypassed = bypassEnabled && isSensitiveBinary(argv);
            reportExecCall("Runtime.exec(String[])", argv, bypassed);
            if (bypassed) {
                return this.exec(Java.array("java.lang.String", buildSpoofedArgv(argv)));
            }
            return this.exec(cmdarray);
        };
    } catch (e) {
        log(MODULE_NAME, "error", `Failed to hook java.lang.Runtime.exec: ${e.stack || e}`);
    }

    try {
        const ProcessBuilder = Java.use("java.lang.ProcessBuilder");
        const Arrays = Java.use("java.util.Arrays");

        ProcessBuilder.start.implementation = function () {
            const argv = javaListToJs(this.command());
            const bypassed = bypassEnabled && isSensitiveBinary(argv);
            reportExecCall("ProcessBuilder.start", argv, bypassed);
            if (bypassed) {
                // Rewrite this ProcessBuilder's own command list in place,
                // then let the real, unmodified start() run it -- no need
                // to fabricate or wrap a Process object at all.
                this.command(Arrays.asList(Java.array("java.lang.String", buildSpoofedArgv(argv))));
            }
            return this.start();
        };
    } catch (e) {
        log(MODULE_NAME, "error", `Failed to hook java.lang.ProcessBuilder: ${e.stack || e}`);
    }
}

function installAndroidJavaHooks() {
    Java.perform(() => {
        hookJavaFileChecks();
        hookJavaRuntimeExec();
    });
}

// --------------------------------------------------------------------
// iOS (Objective-C) hooks
// --------------------------------------------------------------------

/**
 * ObjC methods are plain native functions once resolved: args[0] is
 * `self`, args[1] is the selector (_cmd), and args[2..] are the real
 * parameters -- so this reuses attachSafe() exactly like a libc hook
 * instead of needing a separate ObjC-specific interception mechanism.
 */
function hookObjCPathMethod(clazz, selector, apiLabel) {
    const method = clazz && clazz[selector];
    if (!method) {
        log(MODULE_NAME, "debug", `ObjC selector not found: ${selector}`);
        return;
    }

    attachSafe(MODULE_NAME, method.implementation, {
        onEnter(args) {
            const pathArg = args[2];
            this.path = pathArg.isNull() ? null : new ObjC.Object(pathArg).toString();
            this.suspicious = isSuspiciousPath(this.path);
        },
        onLeave(retval) {
            if (!this.suspicious) return;
            const exists = retval.toInt32() !== 0;
            const bypassed = bypassEnabled && exists;
            reportPathCheck("objc", apiLabel, this.path, { exists, bypassed });
            if (bypassed) retval.replace(0);
        },
    });
    log(MODULE_NAME, "debug", `Hooked ${apiLabel}`);
}

function installIOSObjCHooks() {
    const NSFileManager = ObjC.classes.NSFileManager;
    if (!NSFileManager) {
        log(MODULE_NAME, "warning", "NSFileManager class not found");
        return;
    }
    hookObjCPathMethod(NSFileManager, "- fileExistsAtPath:", "NSFileManager.fileExistsAtPath:");
    hookObjCPathMethod(NSFileManager, "- canOpenFileAtPath:", "NSFileManager.canOpenFileAtPath:");
}

// --------------------------------------------------------------------
// Entry point (called by agents/loader.js)
// --------------------------------------------------------------------

export function init(config = {}) {
    bypassEnabled = Boolean(config.bypass);

    if (Array.isArray(config.extra_markers) && config.extra_markers.length > 0) {
        activeMarkers = [
            ...DEFAULT_SUSPICIOUS_PATH_MARKERS,
            ...config.extra_markers.map((m) => String(m).toLowerCase()),
        ];
    }

    installNativeHooks();

    if (isAndroid()) {
        installAndroidJavaHooks();
    }
    if (isIOS()) {
        installIOSObjCHooks();
    }

    log(MODULE_NAME, "info", "fs_monitor hooks installed", {
        platform: platformInfo.platform,
        android: isAndroid(),
        ios: isIOS(),
        bypass: bypassEnabled,
    });
}
