// Module 4: Native Hooking & Anti-Debugging Diagnostics.
//
// Traces (and, when config.bypass is set, actively neutralizes) the
// classic ptrace-based and /proc-introspection techniques apps use to
// detect Frida/gdb-style instrumentation, plus the exit()/abort()/
// raise() self-destruct calls some anti-debug routines fall back to
// once they've decided something is wrong. Bypass is opt-in and off
// by default, matching fs_monitor/tls_inspector.

import { log, event } from "../common/rpc.js";
import { attachSafe, resolveExport } from "../common/native_utils.js";

const MODULE_NAME = "anti_debug";

let bypassEnabled = false;

function readCString(pointer) {
    if (pointer === null || pointer === undefined || pointer.isNull()) return null;
    try {
        return pointer.readCString();
    } catch (e) {
        return null;
    }
}

// --------------------------------------------------------------------
// ptrace(PTRACE_TRACEME, ...) -- classic "am I already being traced?" check
// --------------------------------------------------------------------

const PTRACE_TRACEME = 0;

function hookPtrace() {
    const resolved = resolveExport([[null, "ptrace"]]);
    if (resolved === null) {
        log(MODULE_NAME, "debug", "ptrace: no matching export found");
        return;
    }
    attachSafe(MODULE_NAME, resolved.address, {
        onEnter(args) {
            this.request = args[0].toInt32();
        },
        onLeave(retval) {
            const isTraceme = this.request === PTRACE_TRACEME;
            const bypassed = bypassEnabled && isTraceme;
            event(MODULE_NAME, "ptrace_call", { request: this.request, isTraceme, bypassed });
            if (bypassed) {
                retval.replace(0);
            }
        },
    });
    log(MODULE_NAME, "debug", `Hooked ptrace -> ${resolved.moduleName}!${resolved.symbolName}`);
}

// --------------------------------------------------------------------
// /proc/self/status + /proc/self/wchan -- TracerPid spoofing
// --------------------------------------------------------------------

// fd -> which proc file it points to ("status" | "wchan"), so a later
// read() on that fd knows whether to filter its content. Evicted on
// close() so a reused fd number never inherits a stale classification.
const trackedFds = new Map();

function classifyProcPath(path) {
    if (typeof path !== "string") return null;
    if (path === "/proc/self/status" || path === `/proc/${Process.id}/status`) return "status";
    if (path === "/proc/self/wchan" || path === `/proc/${Process.id}/wchan`) return "wchan";
    return null;
}

// TracerPid is a plain ASCII line (`TracerPid:\t<digits>\n`) that only
// ever appears in /proc/self/status -- running this over wchan content
// too is a harmless no-op (the regex just won't match), which keeps
// both paths sharing one code path instead of two near-identical ones.
function stripTracerPid(text) {
    return text.replace(/TracerPid:(\s*)\d+/, (_match, sep) => `TracerPid:${sep}0`);
}

function trackProcFdOpens(candidates, apiName, pathArgIndex) {
    const resolved = resolveExport(candidates);
    if (resolved === null) {
        log(MODULE_NAME, "debug", `${apiName}: no matching export found`);
        return;
    }
    attachSafe(MODULE_NAME, resolved.address, {
        onEnter(args) {
            this.kind = classifyProcPath(readCString(args[pathArgIndex]));
        },
        onLeave(retval) {
            if (!this.kind) return;
            const fd = retval.toInt32();
            if (fd < 0) return;
            trackedFds.set(fd, this.kind);
            event(MODULE_NAME, "proc_probe", { api: apiName, kind: this.kind, fd });
        },
    });
    log(MODULE_NAME, "debug", `Hooked ${apiName} for /proc/self tracking -> ${resolved.moduleName}!${resolved.symbolName}`);
}

function hookReadForTracerPidSpoof() {
    const resolved = resolveExport([[null, "read"]]);
    if (resolved === null) {
        log(MODULE_NAME, "debug", "read: no matching export found");
        return;
    }
    attachSafe(MODULE_NAME, resolved.address, {
        onEnter(args) {
            this.fd = args[0].toInt32();
            this.buf = args[1];
            this.kind = trackedFds.get(this.fd) ?? null;
        },
        onLeave(retval) {
            if (!this.kind || !bypassEnabled) return;
            const n = retval.toInt32();
            if (n <= 0) return;
            try {
                const original = this.buf.readCString(n);
                if (original === null) return;
                const filtered = stripTracerPid(original);
                if (filtered === original) return; // nothing to change (e.g. wchan, or already 0)

                // Filtered text is always <= original length (a digit run
                // shrinks to "0"), so writing it back in place, then telling
                // the caller only that many bytes are valid, is always safe.
                const bytes = [];
                for (let i = 0; i < filtered.length; i++) bytes.push(filtered.charCodeAt(i));
                this.buf.writeByteArray(bytes);
                retval.replace(bytes.length);
                event(MODULE_NAME, "anti_debug_bypass", { api: "read", kind: this.kind, fd: this.fd });
            } catch (e) {
                log(MODULE_NAME, "debug", `Failed to filter /proc/self/${this.kind} content: ${e.stack || e}`);
            }
        },
    });
    log(MODULE_NAME, "debug", `Hooked read -> ${resolved.moduleName}!${resolved.symbolName}`);
}

function hookClose() {
    const resolved = resolveExport([[null, "close"]]);
    if (resolved === null) {
        log(MODULE_NAME, "debug", "close: no matching export found");
        return;
    }
    attachSafe(MODULE_NAME, resolved.address, {
        onEnter(args) {
            trackedFds.delete(args[0].toInt32());
        },
    });
}

// --------------------------------------------------------------------
// exit() / abort() / raise() -- forced self-destruct on detection
// --------------------------------------------------------------------

/**
 * exit()/abort()/raise() never return through the normal onLeave path
 * (they're noreturn, or in raise()'s case, fatal in practice for the
 * signals anti-debug code actually raises), so attachSafe's
 * Interceptor.attach can't intercept their outcome -- this needs a full
 * Interceptor.replace(). The original NativeFunction must be captured
 * *before* replacing: afterwards, resolved.address vectors to our own
 * replacement, so calling through it again would recurse.
 */
function hookForcedTermination(candidates, apiName, retType, argTypes, bypassReturnValue) {
    const resolved = resolveExport(candidates);
    if (resolved === null) {
        log(MODULE_NAME, "debug", `${apiName}: no matching export found`);
        return;
    }
    const original = new NativeFunction(resolved.address, retType, argTypes);
    try {
        Interceptor.replace(resolved.address, new NativeCallback((...args) => {
            event(MODULE_NAME, "anti_debug_bypass", { api: apiName, args, bypassed: bypassEnabled });
            if (!bypassEnabled) {
                return original(...args);
            }
            // bypassed: return without calling the real exit()/abort()/raise() --
            // neutralizes whatever self-destruct the app just attempted.
            return bypassReturnValue;
        }, retType, argTypes));
        log(MODULE_NAME, "debug", `Hooked ${apiName} -> ${resolved.moduleName}!${resolved.symbolName}`);
    } catch (e) {
        log(MODULE_NAME, "error", `Failed to hook ${apiName}: ${e.stack || e}`);
    }
}

function installForcedTerminationGuards() {
    hookForcedTermination([[null, "exit"]], "exit", "void", ["int"], undefined);
    hookForcedTermination([[null, "abort"]], "abort", "void", [], undefined);
    hookForcedTermination([[null, "raise"]], "raise", "int", ["int"], 0);
}

// --------------------------------------------------------------------
// Entry point (called by agents/loader.js)
// --------------------------------------------------------------------

export function init(config = {}) {
    bypassEnabled = Boolean(config.bypass);

    hookPtrace();
    trackProcFdOpens([[null, "open"]], "open", 0);
    trackProcFdOpens([[null, "openat"]], "openat", 1);
    hookReadForTracerPidSpoof();
    hookClose();
    installForcedTerminationGuards();

    log(MODULE_NAME, "info", "anti_debug hooks installed", { bypass: bypassEnabled });
}
