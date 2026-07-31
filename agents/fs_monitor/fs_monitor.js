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

const ROOT_PROPERTY_KEYS = new Set([
    "ro.build.tags",
    "ro.build.type",
    "ro.build.selinux",
    "ro.debuggable",
    "ro.secure",
    "ro.boot.verifiedbootstate",
    "ro.boot.flash.locked",
    "ro.boot.veritymode",
]);

// Package identifiers RootBeer-style detectors query PackageManager for
// directly (detectRootManagementApps() / detectPotentiallyDangerousApps()),
// as opposed to checking the filesystem for su/magisk binaries.
const ROOT_MANAGEMENT_PACKAGES = new Set([
    "com.noshufou.android.su",
    "com.noshufou.android.su.elite",
    "eu.chainfire.supersu",
    "com.koushikdutta.superuser",
    "com.thirdparty.superuser",
    "com.yellowes.su",
    "com.topjohnwu.magisk",
    "com.kingroot.kinguser",
    "com.kingo.root",
    "com.smedialink.oneclickroot",
    "com.zhiqupk.root.global",
    "com.alephzain.framaroot",
    "com.koushikdutta.rommanager",
    "com.koushikdutta.rommanager.license",
    "com.dimonvideo.luckypatcher",
    "com.chelpus.lackypatch",
    "com.ramdroid.appquarantine",
    "com.ramdroid.appquarantinepro",
]);

const SU_EXEC_MARKERS = ["su", "which su", "busybox", "magisk"];

// Binaries commonly shelled out to for root/environment fingerprinting.
// When bypass is enabled, invocations of these never actually run --
// their argv is rewritten to a harmless `echo` before the real exec()/
// start() happens, so we never need to intercept or drain a Process's
// output streams (whose concrete class varies by Android version).
const SENSITIVE_EXEC_BINARIES = new Set(["getprop", "mount", "which", "id", "su"]);

// Values a clean, non-rooted device would report for the keys apps most
// commonly probe -- shared between the `getprop <key>` exec spoof below
// and the direct SystemProperties.get() spoof in hookBuildProperties().
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

/**
 * Native equivalent of the Java SystemProperties.get() hook in
 * hookBuildProperties() -- closes the gap where a plugin's native (JNI)
 * code reads a property directly via __system_property_get(), bypassing
 * the Java-level check entirely. Reuses the exact same ROOT_PROPERTY_KEYS/
 * SPOOFED_PROPERTY_VALUES tables so both layers agree on what "clean"
 * looks like.
 */
function hookNativePropertyGet() {
    const resolved = resolveExport([[null, "__system_property_get"]]);
    if (resolved === null) {
        log(MODULE_NAME, "debug", "__system_property_get: no matching export found");
        return;
    }
    attachSafe(MODULE_NAME, resolved.address, {
        onEnter(args) {
            this.name = readCString(args[0]);
            this.valueBuf = args[1];
        },
        onLeave(retval) {
            if (!this.name) return;
            let value = null;
            try {
                value = this.valueBuf.readCString();
            } catch (e) {
                return;
            }
            const suspiciousValue = typeof value === "string" && value.toLowerCase().includes("test-keys");
            if (!ROOT_PROPERTY_KEYS.has(this.name) && !suspiciousValue) return;

            const spoofed = bypassEnabled && Object.prototype.hasOwnProperty.call(SPOOFED_PROPERTY_VALUES, this.name)
                ? SPOOFED_PROPERTY_VALUES[this.name]
                : null;
            const bypassed = spoofed !== null;

            event(MODULE_NAME, "suspicious_property_check", {
                source: "native",
                api: "__system_property_get",
                key: this.name,
                value,
                bypassed,
            });

            if (bypassed) {
                try {
                    const bytes = [];
                    for (let i = 0; i < spoofed.length; i++) bytes.push(spoofed.charCodeAt(i));
                    bytes.push(0); // property values are NUL-terminated C strings
                    this.valueBuf.writeByteArray(bytes);
                    retval.replace(spoofed.length);
                } catch (e) {
                    log(MODULE_NAME, "debug", `Failed to spoof native property ${this.name}: ${e.stack || e}`);
                }
            }
        },
    });
    log(MODULE_NAME, "debug", `Hooked __system_property_get -> ${resolved.moduleName}!${resolved.symbolName}`);
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
    hookNativePropertyGet();
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

function hookBuildProperties() {
    try {
        const Build = Java.use("android.os.Build");
        event(MODULE_NAME, "build_fingerprint", {
            tags: Build.TAGS.value,
            fingerprint: Build.FINGERPRINT.value,
            type: Build.TYPE.value,
            model: Build.MODEL.value,
        });
    } catch (e) {
        log(MODULE_NAME, "error", `Failed to read android.os.Build fields: ${e.stack || e}`);
    }

    // Build.TAGS/FINGERPRINT are `static final` fields populated once from
    // system properties at class-load time -- Frida can intercept method
    // calls, not field reads, so there is no way to "hook" a read of
    // Build.TAGS itself. SystemProperties.get() is the actual choke point:
    // it's what populates those fields in the first place, and it's also
    // what any app code calls directly to re-check ro.build.tags/ro.secure/
    // ro.debuggable at runtime, bypassing android.os.Build entirely.
    try {
        const SystemProperties = Java.use("android.os.SystemProperties");

        const reportGet = (key, value, bypassed = false) => {
            const suspiciousValue = typeof value === "string" && value.toLowerCase().includes("test-keys");
            if (ROOT_PROPERTY_KEYS.has(key) || suspiciousValue) {
                event(MODULE_NAME, "suspicious_property_check", {
                    source: "java",
                    api: "SystemProperties.get",
                    key,
                    value,
                    bypassed,
                });
            }
        };

        const spoofFor = (key) =>
            Object.prototype.hasOwnProperty.call(SPOOFED_PROPERTY_VALUES, key) ? SPOOFED_PROPERTY_VALUES[key] : null;

        SystemProperties.get.overload("java.lang.String").implementation = function (key) {
            const spoofed = bypassEnabled ? spoofFor(key) : null;
            if (spoofed !== null) {
                reportGet(key, spoofed, true);
                return spoofed;
            }
            const value = this.get(key);
            reportGet(key, value);
            return value;
        };

        SystemProperties.get.overload("java.lang.String", "java.lang.String").implementation = function (key, def) {
            const spoofed = bypassEnabled ? spoofFor(key) : null;
            if (spoofed !== null) {
                reportGet(key, spoofed, true);
                return spoofed;
            }
            const value = this.get(key, def);
            reportGet(key, value);
            return value;
        };
    } catch (e) {
        log(MODULE_NAME, "error", `Failed to hook android.os.SystemProperties: ${e.stack || e}`);
    }
}

// "Developer mode" is a distinct concept from root: Android exposes it
// via Settings.Global/Secure ("development_settings_enabled",
// "adb_enabled") and Debug.isDebuggerConnected(). Any device set up to
// run this framework at all (frida-server, adb shell, USB debugging)
// will genuinely have these on, and some apps treat that as its own
// detection signal -- independent of, or in addition to, any root
// check. Traced and spoofed here as its own path rather than folded
// into the root-property checks above.
const DEVELOPER_MODE_SETTINGS_KEYS = new Set(["development_settings_enabled", "adb_enabled"]);

function hookDeveloperModeSettings() {
    ["android.provider.Settings$Global", "android.provider.Settings$Secure"].forEach((className) => {
        let SettingsClass;
        try {
            SettingsClass = Java.use(className);
        } catch (e) {
            return; // class not present on this API level -- fine, try the next one
        }

        try {
            SettingsClass.getInt.overloads.forEach((overload) => {
                overload.implementation = function (...args) {
                    const key = args[1]; // (ContentResolver, String name[, int def])
                    const suspicious = typeof key === "string" && DEVELOPER_MODE_SETTINGS_KEYS.has(key);
                    try {
                        const result = this.getInt(...args);
                        const bypassed = bypassEnabled && suspicious && result !== 0;
                        if (suspicious) {
                            event(MODULE_NAME, "suspicious_setting_check", {
                                source: "java", api: `${className}.getInt`, key, value: result, bypassed,
                            });
                        }
                        return bypassed ? 0 : result;
                    } catch (e) {
                        // 2-arg overload throws Settings.SettingNotFoundException when
                        // absent -- report it, then re-throw to preserve real behavior.
                        // Nothing to bypass here: "not found" already reads as "off".
                        if (suspicious) {
                            event(MODULE_NAME, "suspicious_setting_check", {
                                source: "java", api: `${className}.getInt`, key, error: String(e), bypassed: false,
                            });
                        }
                        throw e;
                    }
                };
            });
        } catch (e) {
            log(MODULE_NAME, "debug", `${className}.getInt not present: ${e.message}`);
        }
    });

    try {
        const Debug = Java.use("android.os.Debug");
        Debug.isDebuggerConnected.implementation = function () {
            const result = this.isDebuggerConnected();
            event(MODULE_NAME, "suspicious_setting_check", {
                source: "java", api: "Debug.isDebuggerConnected", value: result,
            });
            return result;
        };
    } catch (e) {
        log(MODULE_NAME, "debug", `Debug.isDebuggerConnected not present: ${e.message}`);
    }
}

/**
 * RootBeer-style detectors don't only check the filesystem for su/magisk
 * binaries -- detectRootManagementApps()/detectPotentiallyDangerousApps()
 * query PackageManager directly, either per-package (getPackageInfo/
 * getApplicationInfo, which throw NameNotFoundException when absent) or
 * by scanning the full installed-app list. Both call sites are handled
 * here so either style of check gets the same "not installed" answer.
 */
function hookPackageManagerRootAppChecks() {
    try {
        // getPackageInfo()/getApplicationInfo() are implemented on the
        // concrete manager Context.getPackageManager() returns, not on the
        // abstract PackageManager class itself.
        const AppPackageManager = Java.use("android.app.ApplicationPackageManager");
        const NameNotFoundException = Java.use("android.content.pm.PackageManager$NameNotFoundException");

        ["getPackageInfo", "getApplicationInfo"].forEach((methodName) => {
            try {
                AppPackageManager[methodName].overloads.forEach((overload) => {
                    overload.implementation = function (packageName, flags) {
                        const suspicious = ROOT_MANAGEMENT_PACKAGES.has(packageName);
                        const bypassed = bypassEnabled && suspicious;
                        if (suspicious) {
                            event(MODULE_NAME, "suspicious_package_check", {
                                source: "java",
                                api: `PackageManager.${methodName}`,
                                package: packageName,
                                bypassed,
                            });
                        }
                        if (bypassed) {
                            throw NameNotFoundException.$new(packageName);
                        }
                        return this[methodName](packageName, flags);
                    };
                });
            } catch (e) {
                log(MODULE_NAME, "debug", `PackageManager.${methodName} not present on this build`);
            }
        });

        const filterInstalledList = (methodName, entryClassName) => {
            try {
                const EntryClass = Java.use(entryClassName);
                AppPackageManager[methodName].overloads.forEach((overload) => {
                    overload.implementation = function (flags) {
                        const list = this[methodName](flags);
                        if (!bypassEnabled) return list;

                        const filtered = Java.use("java.util.ArrayList").$new();
                        const it = list.iterator();
                        let removedAny = false;
                        while (it.hasNext()) {
                            const rawEntry = it.next();
                            const entry = Java.cast(rawEntry, EntryClass);
                            if (ROOT_MANAGEMENT_PACKAGES.has(entry.packageName.value)) {
                                removedAny = true;
                                continue;
                            }
                            filtered.add(rawEntry);
                        }
                        if (removedAny) {
                            event(MODULE_NAME, "suspicious_package_check", {
                                source: "java",
                                api: `PackageManager.${methodName}`,
                                bypassed: true,
                            });
                        }
                        return filtered;
                    };
                });
            } catch (e) {
                log(MODULE_NAME, "debug", `PackageManager.${methodName} not present on this build`);
            }
        };

        filterInstalledList("getInstalledApplications", "android.content.pm.ApplicationInfo");
        filterInstalledList("getInstalledPackages", "android.content.pm.PackageInfo");
    } catch (e) {
        log(MODULE_NAME, "error", `Failed to hook PackageManager root-app checks: ${e.stack || e}`);
    }
}

/**
 * RootBeer (scottyab/rootbeer) ships a `native` Java method specifically
 * so a naive Java-only hooking script misses it -- but `.implementation =`
 * intercepts at the ART method-dispatch level regardless of whether the
 * body is Java bytecode or a JNI trampoline into a bundled .so, so this
 * still catches it before the native code ever runs.
 */
function hookRootBeerNative() {
    let RootBeerNative;
    try {
        RootBeerNative = Java.use("com.scottyab.rootbeer.RootBeerNative");
    } catch (e) {
        return; // library not present in this app -- nothing to do
    }

    try {
        RootBeerNative.checkForRoot.implementation = function (cLibraryPaths) {
            const realResult = this.checkForRoot(cLibraryPaths);
            const bypassed = bypassEnabled && Boolean(realResult);
            event(MODULE_NAME, "suspicious_native_check", {
                source: "java-jni",
                api: "RootBeerNative.checkForRoot",
                result: realResult,
                bypassed,
            });
            // Declared `native int checkForRoot(...)`, not `boolean` --
            // returning the JS boolean `false` here throws "expected return
            // value compatible with int" (confirmed by an actual crash
            // hitting this exact path). 0 is RootBeer's own "not rooted".
            return bypassed ? 0 : realResult;
        };
        log(MODULE_NAME, "debug", "Hooked com.scottyab.rootbeer.RootBeerNative.checkForRoot");
    } catch (e) {
        // Signature may differ across RootBeer forks/versions -- log the
        // class's actual declared methods so the real one can be targeted.
        try {
            const methodNames = RootBeerNative.class.getDeclaredMethods().map((m) => m.getName());
            log(MODULE_NAME, "warning", `RootBeerNative present but checkForRoot() hook failed; declared methods: ${methodNames.join(", ")}`);
        } catch (e2) {
            log(MODULE_NAME, "error", `Failed to hook RootBeerNative: ${e.stack || e}`);
        }
    }
}

/**
 * Defense in depth: hook RootBeer's own top-level public API too, not
 * just its individual leaf checks. RootBeer's checklist includes things
 * this module doesn't separately replicate (e.g. checking whether
 * /system is mounted read-write) -- catching the aggregate result covers
 * those without needing to chase every leaf check one at a time.
 */
function hookRootBeerAggregate() {
    let RootBeer;
    try {
        RootBeer = Java.use("com.scottyab.rootbeer.RootBeer");
    } catch (e) {
        return;
    }

    ["isRooted", "isRootedWithoutBusyBoxCheck"].forEach((methodName) => {
        try {
            RootBeer[methodName].implementation = function () {
                const realResult = this[methodName]();
                const bypassed = bypassEnabled && realResult;
                event(MODULE_NAME, "suspicious_native_check", {
                    source: "java",
                    api: `RootBeer.${methodName}`,
                    result: realResult,
                    bypassed,
                });
                return bypassed ? false : realResult;
            };
            log(MODULE_NAME, "debug", `Hooked com.scottyab.rootbeer.RootBeer.${methodName}`);
        } catch (e) {
            log(MODULE_NAME, "debug", `RootBeer.${methodName} not present: ${e.message}`);
        }
    });
}

function installAndroidJavaHooks() {
    Java.perform(() => {
        hookJavaFileChecks();
        hookJavaRuntimeExec();
        hookBuildProperties();
        hookDeveloperModeSettings();
        hookPackageManagerRootAppChecks();
        hookRootBeerNative();
        hookRootBeerAggregate();
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
