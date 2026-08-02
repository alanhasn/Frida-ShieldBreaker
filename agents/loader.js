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
import * as recon from "./recon/recon.js";
import * as flutterTls from "./flutter_tls/flutter_tls.js";
import { selectModulesForDetectedFrameworks } from "./framework_detection/detector.js";

const MODULE_NAME = "loader";

const MODULE_REGISTRY = {
    fs: fsMonitor,
    tls: tlsInspector,
    antidebug: antiDebug,
    recon,
    flutter_tls: flutterTls,
};

/**
 * Payload shape posted by core/loader.py's `load_agent(..., init_payload=...)`:
 *   {
 *     enabled_modules: string[],   // e.g. ["fs", "tls", "antidebug"] -- omitted when auto_detect is true
 *     module_config: { [name]: object },   // optional per-module options
 *     default_bypass: boolean,     // applied to every enabled module unless overridden in module_config
 *     auto_detect: boolean,        // when true, the module list comes from framework_detection instead
 *   }
 */
function bootstrap(initPayload) {
    const payload = initPayload ?? {};
    const moduleConfig = payload.module_config ?? {};
    const defaultBypass = Boolean(payload.default_bypass);

    // enabled_modules is only meaningful (and only sent) when auto_detect
    // is false -- see main.py's cmd_run. Detection itself only ever runs
    // once per process regardless of how bootstrap ends up being invoked,
    // since detectFrameworks() memoizes its result.
    const enabled = payload.auto_detect
        ? selectModulesForDetectedFrameworks()
        : payload.enabled_modules ?? Object.keys(MODULE_REGISTRY);

    log(
        MODULE_NAME,
        "info",
        `Bootstrapping on ${platformInfo.platform}/${platformInfo.arch}; modules=[${enabled.join(", ")}]` +
            (payload.auto_detect ? " (auto-detected)" : "")
    );

    const initialized = [];
    for (const name of enabled) {
        const mod = MODULE_REGISTRY[name];
        if (!mod) {
            log(MODULE_NAME, "warning", `Unknown module requested: '${name}'`);
            continue;
        }
        const config = { bypass: defaultBypass, ...(moduleConfig[name] ?? {}) };
        try {
            mod.init(config);
            initialized.push(name);
        } catch (e) {
            log(MODULE_NAME, "error", `Module '${name}' threw during init(): ${e.stack || e}`);
        }
    }

    rpc.ready(MODULE_NAME, {
        enabled_modules: initialized,
        auto_detect: Boolean(payload.auto_detect),
        platform: platformInfo.platform,
        arch: platformInfo.arch,
    });
}

rpc.once("init", bootstrap);
