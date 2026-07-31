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

/** Reads a NUL-terminated C string from `pointer`, or null on a null pointer or read failure. */
export function readCString(pointer) {
    if (pointer === null || pointer === undefined || pointer.isNull()) return null;
    try {
        return pointer.readCString();
    } catch (e) {
        return null;
    }
}

/**
 * Returns every currently loaded module whose name case-insensitively
 * equals, or contains as a substring, one of `candidateNames`. Substring
 * matching covers platform/vendor naming variance (e.g. a renamed copy of
 * a shared object, or a bare framework binary name on iOS) without any
 * caller needing to hardcode an exact name. Used for locating a specific
 * embedded runtime (e.g. a cross-platform framework's own native library)
 * rather than resolving a symbol against whatever module happens to
 * export it first.
 */
export function findModules(candidateNames) {
    if (!Array.isArray(candidateNames) || candidateNames.length === 0) return [];
    const lowerCandidates = candidateNames.map((name) => String(name).toLowerCase());
    try {
        return Process.enumerateModules().filter((m) => {
            const lowerName = m.name.toLowerCase();
            return lowerCandidates.some((candidate) => lowerName === candidate || lowerName.includes(candidate));
        });
    } catch (e) {
        return [];
    }
}
