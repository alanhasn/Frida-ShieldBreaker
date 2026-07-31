// Shared helpers for framework detectors (see detector.js). Kept in
// their own file, separate from detector.js itself, purely to avoid a
// circular import -- detector.js imports every individual detector
// module, so those modules can't import back from detector.js.

/**
 * Combines a list of independent evidence checks into a single 0-100
 * confidence score. Each `{ present, weight, label }` check contributes
 * `weight` to the score only when `present` is true, and `label` is
 * collected as human-readable evidence in the same case -- so the
 * returned evidence list always explains exactly where the score came
 * from. A negative `weight` is valid and means the check is evidence
 * *against* the framework (see native_android.js, which is defined by
 * the absence of other frameworks' markers). The total is clamped to
 * the 0-100 range every detector reports on.
 */
export function scoreEvidence(checks) {
    let score = 0;
    const evidence = [];
    for (const { present, weight, label } of checks) {
        if (present) {
            score += weight;
            evidence.push(label);
        }
    }
    return { confidence: Math.max(0, Math.min(100, score)), evidence };
}

/**
 * Presence-only check for a Java class name. Must be called from inside
 * a Java.perform() callback (not wrapped here itself, so a detector that
 * needs to check several classes only pays for one Java.perform() call,
 * not one per class).
 */
export function javaClassPresent(className) {
    try {
        Java.use(className);
        return true;
    } catch (e) {
        return false;
    }
}
