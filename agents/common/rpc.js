// Shared IPC helpers used by every agent module to talk back to the
// Python host. Every outbound message is wrapped in the envelope
// `core/ipc.py` expects: { type, module, payload }. Modules should
// never call the raw global `send()` directly -- go through these
// helpers so the envelope shape stays consistent across
// fs_monitor / tls_inspector / anti_debug.

function envelope(type, moduleName, payload) {
    send({ type, module: moduleName, payload });
}

/** Structured log line, rendered by core/ipc.py through the Rich logger. */
export function log(moduleName, level, message, extra = {}) {
    envelope("log", moduleName, { level, message, ...extra });
}

// Monotonic per-agent counter so any two events, from any module, can be
// placed in an unambiguous total order -- e.g. to reconstruct a
// decision-flow timeline (native check -> platform-channel reply ->
// UI reaction) from the interleaved log stream after the fact.
let eventSequence = 0;

/** A discrete finding/observation, e.g. "root check bypassed". */
export function event(moduleName, name, payload = {}) {
    eventSequence += 1;
    // name/seq/ts placed after the payload spread so a payload field of
    // the same name can never accidentally shadow them.
    envelope("event", moduleName, { ...payload, name, seq: eventSequence, ts: Date.now() });
}

/** Signals that a module finished initializing and installed its hooks. */
export function ready(moduleName, payload = {}) {
    envelope("ready", moduleName, payload);
}

// Frida's recv(type, callback) is single-shot: once the callback runs
// it must be re-registered to receive the next message of that type.
// `on()` re-arms itself automatically so callers get a persistent
// listener; `once()` intentionally does not, for one-time handshakes
// like the initial `init` payload.

/** Persistent listener for messages of `type` posted via script.post(). */
export function on(type, handler) {
    function listen() {
        recv(type, (message) => {
            try {
                handler(message.payload);
            } catch (e) {
                log("rpc", "error", `Handler for '${type}' threw: ${e.stack || e}`);
            } finally {
                listen();
            }
        });
    }
    listen();
}

/** One-shot listener for messages of `type`. Does not re-arm after delivery. */
export function once(type, handler) {
    recv(type, (message) => {
        handler(message.payload);
    });
}

export const rpc = { log, event, ready, on, once };
