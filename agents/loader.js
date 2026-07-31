// Primary agent entry point. Bundled by frida-compile into
// agents/dist/agent.js and injected as-is by core/loader.py.
//
// Responsibilities:
//   1. Register the init handshake *synchronously* -- core/loader.py
//      calls session.create_script(source).load() and then immediately
//      posts {"type": "init", "payload": {...}}. If our recv('init', ...)
//      isn't registered before that post() happens, the message is lost.
//      That's why bootstrapping is wired at the top level, not inside a
//      promise/timeout.
//   2. Fan the enabled module list out to each sub-module's init().
//   3. Keep failures in one module (bad hook, missing symbol) from
//      taking down the others.

import { rpc, log } from "./common/rpc.js";
import { platformInfo } from "./common/native_utils.js";
import * as fsMonitor from "./fs_monitor/fs_monitor.js";
import * as tlsInspector from "./tls_inspector/tls_inspector.js";
import * as antiDebug from "./anti_debug/anti_debug.js";

const MODULE_NAME = "loader";

const MODULE_REGISTRY = {
    fs: fsMonitor,
    tls: tlsInspector,
    antidebug: antiDebug,
};

/**
 * Payload shape posted by core/loader.py's `load_agent(..., init_payload=...)`:
 *   {
 *     enabled_modules: string[],           // e.g. ["fs", "tls", "antidebug"]
 *     module_config: { [name]: object },   // optional per-module options
 *   }
 */
function bootstrap(initPayload) {
    const payload = initPayload ?? {};
    const enabled = payload.enabled_modules ?? Object.keys(MODULE_REGISTRY);
    const moduleConfig = payload.module_config ?? {};

    log(
        MODULE_NAME,
        "info",
        `Bootstrapping on ${platformInfo.platform}/${platformInfo.arch}; modules=[${enabled.join(", ")}]`
    );

    const initialized = [];
    for (const name of enabled) {
        const mod = MODULE_REGISTRY[name];
        if (!mod) {
            log(MODULE_NAME, "warning", `Unknown module requested: '${name}'`);
            continue;
        }
        try {
            mod.init(moduleConfig[name] ?? {});
            initialized.push(name);
        } catch (e) {
            log(MODULE_NAME, "error", `Module '${name}' threw during init(): ${e.stack || e}`);
        }
    }

    rpc.ready(MODULE_NAME, { enabled_modules: initialized });
}

rpc.once("init", bootstrap);
