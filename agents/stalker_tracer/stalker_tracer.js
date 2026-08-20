// Module: Native Instruction Tracer (Stalker + CModule).
//
// Every other module in this framework hooks a *known address*
// (Interceptor.attach/replace on an exported symbol). That's precise and
// cheap, but it can't see code with no symbol to name -- an
// OLLVM-flattened routine, an inlined helper, or a raw `svc #0` syscall
// buried inside a larger function. Stalker fills that gap: it follows a
// specific OS thread's actual execution path and recompiles each basic
// block into an instrumented copy as it runs, so it doesn't need a
// symbol -- it needs a starting thread.
//
// The cost of that power is real: calling back into JavaScript on every
// traced instruction would visibly stall the target. So the hot path
// (what runs on every instruction *execution*) is a native C function
// compiled at runtime via CModule (see native_source.js) and handed to
// Stalker as a raw function pointer -- Stalker calls it directly, no
// JS/V8 crossing per hit. JavaScript only runs at block *compile* time
// (deciding whether a given instruction is worth instrumenting at all --
// see buildInstructionFilter()) and when a caller explicitly asks to
// drain the buffer -- both comparatively rare compared to execution
// count.
//
// Unlike every other module, this one doesn't do anything on its own
// once initialized: it's driven interactively via Frida's own
// rpc.exports (see the bottom of this file), from Python, for the
// exact reason a fixed "trace everything from init() onward" mode would
// be both wasteful and useless -- a real analysis session needs to
// start/stop/inspect tracing against a specific thread while the app is
// already running, not decide up front. A `config.auto_start` escape
// hatch exists for non-interactive/scripted use.
//
// Never enabled by automatic framework detection (see
// agents/framework_detection/detector.js's FRAMEWORK_MODULE_MAP) -- this
// has real performance cost even filtered, and has no passive-observe
// mode, so it stays opt-in only (--modules stalker_tracer).

import { log, event } from "../common/rpc.js";
import { platformInfo } from "../common/native_utils.js";
import { NATIVE_TRACER_SOURCE, RING_CAPACITY, RECORD_SIZE_BYTES } from "./native_source.js";

const MODULE_NAME = "stalker_tracer";

// --------------------------------------------------------------------
// CModule lifecycle
// --------------------------------------------------------------------

let cModule = null;
let cModuleUnavailableReason = null;

/**
 * Compiles the native hot path exactly once. Failure isn't fatal --
 * every caller that needs it falls back to a slower, pure-JS callout
 * instead (see jsFallbackCallout below), so tracing still works on a
 * device/toolchain where CModule compilation isn't available, just
 * without the zero-latency guarantee.
 */
function ensureCModule() {
    if (cModule !== null || cModuleUnavailableReason !== null) return cModule;
    try {
        cModule = new CModule(NATIVE_TRACER_SOURCE);
        event(MODULE_NAME, "cmodule_compiled", {});
        log(MODULE_NAME, "info", "Native (CModule) trace hot path compiled successfully");
    } catch (e) {
        cModuleUnavailableReason = String(e.message || e);
        event(MODULE_NAME, "cmodule_compile_failed", { reason: cModuleUnavailableReason });
        log(MODULE_NAME, "warning", `CModule compilation failed, falling back to JS trace mode: ${cModuleUnavailableReason}`);
    }
    return cModule;
}

function resetNativeBuffer() {
    cModule.sequence.writeU64(0);
}

/** Reads the native ring buffer directly via pointer arithmetic -- no native "drain" function/ABI needed. */
function drainNativeRecords(maxRecords) {
    const total = cModule.sequence.readU64().toNumber();
    const count = Math.max(0, Math.min(maxRecords, total, RING_CAPACITY));
    const start = total - count;
    const records = [];
    for (let i = 0; i < count; i++) {
        const slot = (start + i) % RING_CAPACITY;
        const recordPtr = cModule.ring.add(slot * RECORD_SIZE_BYTES);
        const seq = recordPtr.readU64();
        const addressValue = recordPtr.add(8).readU64();
        records.push({ seq: seq.toNumber(), address: ptr("0x" + addressValue.toString(16)) });
    }
    return { total, dropped: Math.max(0, total - RING_CAPACITY), records };
}

// --------------------------------------------------------------------
// Pure-JS fallback path (used only if CModule compilation failed)
// --------------------------------------------------------------------

const jsRing = new Array(RING_CAPACITY);
let jsSequence = 0;

function jsFallbackCallout(context) {
    const slot = jsSequence % RING_CAPACITY;
    const pc = context.pc ?? context.rip ?? context.eip ?? ptr(0);
    jsRing[slot] = { seq: jsSequence, address: pc };
    jsSequence++;
}

function resetJsBuffer() {
    jsSequence = 0;
    jsRing.length = 0;
}

function drainJsRecords(maxRecords) {
    const total = jsSequence;
    const count = Math.max(0, Math.min(maxRecords, total, RING_CAPACITY));
    const start = total - count;
    const records = [];
    for (let i = 0; i < count; i++) {
        const rec = jsRing[(start + i) % RING_CAPACITY];
        if (rec) records.push(rec);
    }
    return { total, dropped: Math.max(0, total - RING_CAPACITY), records };
}

// --------------------------------------------------------------------
// Scope & filtering
// --------------------------------------------------------------------

// Instruction-mnemonic presets. "syscalls" targets svc on ARM/ARM64
// (svc #0 is the standard AArch64/ARM Linux syscall trap -- x86 targets
// aren't in scope for this preset since they use a different mechanism
// entirely, int 0x80/syscall, not a named mnemonic worth conflating
// here). "calls" targets branch-with-link/call instructions across
// ARM64 and x86, useful for mapping control flow through an
// OLLVM-flattened dispatcher without tracing every single instruction.
const MNEMONIC_PRESETS = {
    syscalls: new Set(["svc"]),
    calls: new Set(["bl", "blr", "call", "callq"]),
};

function buildInstructionFilter(filterConfig) {
    if (!filterConfig || filterConfig === "all") return () => true;
    if (Array.isArray(filterConfig)) {
        const set = new Set(filterConfig);
        return (instruction) => set.has(instruction.mnemonic);
    }
    const preset = MNEMONIC_PRESETS[filterConfig];
    if (preset) return (instruction) => preset.has(instruction.mnemonic);
    log(MODULE_NAME, "warning", `Unknown filter preset '${filterConfig}'; tracing all instructions`);
    return () => true;
}

/** Resolves each requested module name to its loaded address range, via Process.findModuleByName(). */
function computeTargetRanges(moduleNames) {
    const ranges = [];
    for (const name of moduleNames) {
        const mod = Process.findModuleByName(name);
        if (mod) {
            ranges.push({ name, base: mod.base, end: mod.base.add(mod.size) });
        } else {
            log(MODULE_NAME, "warning", `Module not found for range filtering: ${name}`);
        }
    }
    return ranges;
}

function addressInRanges(address, ranges) {
    if (ranges.length === 0) return true; // no scoping requested -- trace everywhere (opt-in, expensive)
    return ranges.some((r) => address.compare(r.base) >= 0 && address.compare(r.end) < 0);
}

/**
 * Tells Stalker to skip instrumenting every loaded module *except* the
 * ones we actually want -- the real lever against freezing the app.
 * Stalker has to recompile every block that executes on a followed
 * thread unless the containing range is excluded, so on a narrow target
 * (e.g. one native library) this is the difference between tracing just
 * that library and re-instrumenting the entire Android runtime underneath
 * it. Best-effort per range: a failure to exclude one module doesn't
 * abort the rest.
 */
function excludeNonTargetModules(ranges) {
    if (ranges.length === 0) return 0;
    const targetNames = new Set(ranges.map((r) => r.name));
    let excluded = 0;
    for (const mod of Process.enumerateModules()) {
        if (targetNames.has(mod.name)) continue;
        try {
            Stalker.exclude({ base: mod.base, size: mod.size });
            excluded++;
        } catch (e) {
            // best-effort -- some ranges may already be excluded or unsupported
        }
    }
    return excluded;
}

function describeAddress(address) {
    try {
        const mod = Process.findModuleByAddress(address);
        if (mod) return `${mod.name}!0x${address.sub(mod.base).toString(16)}`;
    } catch (e) {
        // best-effort only
    }
    return address.toString();
}

/** Collapses raw per-hit records into a frequency table -- the useful RE signal is *where*, not a full play-by-play. */
function summarizeRecords(records) {
    const counts = new Map();
    for (const r of records) {
        const key = r.address.toString();
        const entry = counts.get(key);
        if (entry) entry.count += 1;
        else counts.set(key, { address: key, label: describeAddress(r.address), count: 1 });
    }
    return [...counts.values()].sort((a, b) => b.count - a.count).slice(0, 200);
}

function makeTransform(ranges, instructionFilter, callout) {
    return function (iterator) {
        let instruction = iterator.next();
        do {
            if (addressInRanges(instruction.address, ranges) && instructionFilter(instruction)) {
                iterator.putCallout(callout);
            }
            iterator.keep();
        } while ((instruction = iterator.next()) !== null);
    };
}

// --------------------------------------------------------------------
// Session lifecycle
// --------------------------------------------------------------------

// threadId -> { threadId, modules, filter, native, excludedModuleCount, startedAt }
const activeSessions = new Map();

function startTrace(options = {}) {
    const threadId = options.threadId;
    if (!Number.isInteger(threadId)) {
        throw new Error("threadId is required (see stalkerListThreads for valid ids)");
    }
    if (activeSessions.has(threadId)) {
        return { started: false, reason: "already_tracing", threadId };
    }

    const moduleNames = Array.isArray(options.modules) ? options.modules.map(String) : [];
    const ranges = computeTargetRanges(moduleNames);
    const excludeOthers = options.excludeOthers !== false;
    const excludedModuleCount = excludeOthers && ranges.length > 0 ? excludeNonTargetModules(ranges) : 0;

    const instructionFilter = buildInstructionFilter(options.filter);
    const wantNative = options.native !== false;
    const useNative = wantNative && ensureCModule() !== null;

    if (useNative) resetNativeBuffer();
    else resetJsBuffer();

    const callout = useNative ? cModule.on_hit : jsFallbackCallout;

    try {
        Stalker.follow(threadId, { transform: makeTransform(ranges, instructionFilter, callout) });
    } catch (e) {
        return { started: false, reason: "stalker_follow_failed", error: String(e.message || e) };
    }

    const session = {
        threadId,
        modules: moduleNames,
        filter: options.filter ?? "all",
        native: useNative,
        excludedModuleCount,
        startedAt: Date.now(),
    };
    activeSessions.set(threadId, session);

    event(MODULE_NAME, "trace_started", {
        thread_id: threadId,
        modules: moduleNames,
        filter: session.filter,
        native: useNative,
        excluded_module_count: excludedModuleCount,
    });

    return { started: true, threadId, native: useNative, excludedModuleCount };
}

function stopTrace(threadId) {
    if (!Number.isInteger(threadId)) {
        throw new Error("threadId is required");
    }
    const session = activeSessions.get(threadId);
    if (!session) {
        return { stopped: false, reason: "not_tracing", threadId };
    }

    try {
        Stalker.unfollow(threadId);
        Stalker.flush();
    } catch (e) {
        log(MODULE_NAME, "warning", `Stalker.unfollow failed for thread ${threadId}: ${e.stack || e}`);
    }
    activeSessions.delete(threadId);

    const { total, dropped } = session.native ? drainNativeRecords(0) : drainJsRecords(0);
    const durationMs = Date.now() - session.startedAt;

    event(MODULE_NAME, "trace_stopped", {
        thread_id: threadId,
        duration_ms: durationMs,
        total_hits: total,
        dropped,
    });

    return { stopped: true, threadId, totalHits: total, durationMs };
}

function getStatus() {
    const sessions = [...activeSessions.values()].map((s) => ({
        threadId: s.threadId,
        modules: s.modules,
        filter: s.filter,
        native: s.native,
        excludedModuleCount: s.excludedModuleCount,
        elapsedMs: Date.now() - s.startedAt,
    }));
    return {
        activeSessions: sessions,
        cModuleAvailable: cModule !== null,
        cModuleUnavailableReason,
        platform: platformInfo.platform,
        arch: platformInfo.arch,
    };
}

function drainAndReport(threadId, maxRecords) {
    const session = activeSessions.get(threadId);
    if (!session) {
        throw new Error(`No active trace session for thread ${threadId}`);
    }
    const { total, dropped, records } = session.native ? drainNativeRecords(maxRecords) : drainJsRecords(maxRecords);
    const topAddresses = summarizeRecords(records);

    event(MODULE_NAME, "trace_summary", {
        thread_id: threadId,
        total_hits: total,
        dropped,
        sampled: records.length,
        top_addresses: topAddresses,
    });

    return { threadId, total, dropped, sampled: records.length, topAddresses };
}

function listThreads() {
    return Process.enumerateThreads().map((t) => ({ id: t.id, state: t.state }));
}

// --------------------------------------------------------------------
// RPC interface -- Frida's own global `rpc.exports` (NOT this project's
// agents/common/rpc.js `rpc` helper, which is intentionally imported
// above as just { log, event } to avoid shadowing this global). This is
// what lets Python call into a live session interactively -- see
// main.py's --interactive mode -- instead of only reacting to the
// one-shot init payload every other module is limited to. frida-python
// exposes these as snake_case (e.g. stalkerStart -> stalker_start).
// --------------------------------------------------------------------

rpc.exports = {
    stalkerCapabilities() {
        return {
            platform: platformInfo.platform,
            arch: platformInfo.arch,
            cModuleAvailable: ensureCModule() !== null,
            cModuleUnavailableReason,
        };
    },
    stalkerListThreads() {
        return listThreads();
    },
    stalkerStart(options) {
        return startTrace(options ?? {});
    },
    stalkerStop(threadId) {
        return stopTrace(threadId);
    },
    stalkerStatus() {
        return getStatus();
    },
    stalkerDrain(threadId, maxRecords) {
        return drainAndReport(threadId, maxRecords ?? 500);
    },
};

// --------------------------------------------------------------------
// Entry point (called by agents/loader.js)
// --------------------------------------------------------------------

export function init(config = {}) {
    event(MODULE_NAME, "stalker_engine_ready", {
        platform: platformInfo.platform,
        arch: platformInfo.arch,
    });
    log(
        MODULE_NAME,
        "info",
        "stalker_tracer ready -- control interactively via RPC (stalkerStart/stalkerStop/stalkerStatus/" +
            "stalkerDrain/stalkerListThreads) or set config.auto_start for a non-interactive run"
    );

    if (config.native !== false) {
        // Pre-compile eagerly so the first stalkerStart() call (interactive
        // or automatic) doesn't pay the one-time compile cost.
        ensureCModule();
    }

    if (config.auto_start) {
        // Process.getCurrentThreadId() here is whatever thread the agent's
        // own init() happens to run on, which Frida does not guarantee is
        // any particular *application* thread -- fine for a documented
        // smoke-test default, but real usage should pass config.thread_id
        // explicitly (see stalkerListThreads).
        const threadId = Number.isInteger(config.thread_id) ? config.thread_id : Process.getCurrentThreadId();
        const result = startTrace({
            threadId,
            modules: config.modules,
            filter: config.filter,
            native: config.native,
            excludeOthers: config.exclude_others,
        });
        log(MODULE_NAME, "info", `auto_start trace result: ${JSON.stringify(result)}`);
    }
}
