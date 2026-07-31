// Cross-arch/platform helpers shared by every hooking module. Wraps
// the raw Gum/Java/ObjC APIs with defensive lookups so a missing
// symbol on one OEM's build (e.g. a renamed libc export) logs a
// warning instead of taking down the whole agent.

import { log } from "./rpc.js";

export const platformInfo = Object.freeze({
    platform: Process.platform,      // 'linux' | 'darwin' | 'windows' | ...
    arch: Process.arch,              // 'ia32' | 'x64' | 'arm' | 'arm64'
    pointerSize: Process.pointerSize,
});

export function isAndroid() {
    return typeof Java !== "undefined" && Java.available;
}

export function isIOS() {
    return typeof ObjC !== "undefined" && ObjC.available;
}

/**
 * Resolves an export by trying a list of [moduleName, symbolName]
 * candidates in order and returning the first hit. Useful for symbols
 * that move between shared objects across OS/vendor versions, e.g.
 * TLS write primitives living in libssl.so vs. a vendor's statically
 * linked libboringssl.so.
 */
export function resolveExport(candidates) {
    for (const [moduleName, symbolName] of candidates) {
        try {
            const address = Module.findExportByName(moduleName, symbolName);
            if (address !== null) {
                return { address, moduleName, symbolName };
            }
        } catch (e) {
            // Module not loaded (yet) in this process -- try the next candidate.
        }
    }
    return null;
}

/**
 * Interceptor.attach wrapper that never lets one bad hook take down
 * every other module's instrumentation. Failures are logged and
 * swallowed so unrelated hooks (fs_monitor, tls_inspector, ...) keep running.
 */
export function attachSafe(moduleTag, address, callbacks) {
    if (address === null || address === undefined) {
        log(moduleTag, "warning", "attachSafe called with a null address; skipping hook");
        return null;
    }
    try {
        return Interceptor.attach(address, callbacks);
    } catch (e) {
        log(moduleTag, "error", `Failed to attach at ${address}: ${e.stack || e}`);
        return null;
    }
}

/** Enumerates currently loaded module names -- handy for one-off debugging. */
export function listLoadedModules() {
    return Process.enumerateModules().map((m) => m.name);
}

export function bytesToHex(buffer) {
    return Array.from(new Uint8Array(buffer))
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");
}
