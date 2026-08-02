"""Translates raw agent events into human-readable report findings.

Every event name any module emits (see `agents/*/*.js`) should have an
entry in `INTERPRETERS` below: a `(category, describe)` pair, where
`describe(payload)` returns `(title, description, severity)`. An event
name with no registered interpreter still produces a usable finding via
`_describe_generic` -- nothing is ever silently dropped from a report,
it's just less nicely worded until an interpreter is added for it.

Adding a new module's events to the report: add one entry per event name
to `INTERPRETERS`. Nothing else in this file, or in `core/report/model.py`
or any renderer, needs to change.
"""

from __future__ import annotations

from typing import Any, Callable

from core.report.model import Finding, InterpretedFinding

Describer = Callable[[dict[str, Any]], tuple[str, str, str]]  # payload -> (title, description, severity)


def _bypassed(payload: dict[str, Any]) -> bool:
    return bool(payload.get("bypassed"))


def _severity_for_check(payload: dict[str, Any]) -> str:
    """Standard severity rule for a "we observed X, and optionally bypassed it" finding."""
    return "high" if _bypassed(payload) else "medium"


def _suffix_for_check(payload: dict[str, Any]) -> str:
    return " -- bypassed" if _bypassed(payload) else " -- observed only (bypass not enabled or not applicable)"


def _join_evidence(evidence: Any) -> str:
    if isinstance(evidence, list) and evidence:
        return "; ".join(str(e) for e in evidence)
    return "no supporting evidence reported"


# --------------------------------------------------------------------
# fs_monitor
# --------------------------------------------------------------------


def _describe_suspicious_path_check(p: dict[str, Any]) -> tuple[str, str, str]:
    path = p.get("path", "?")
    api = p.get("api", "?")
    exists = p.get("exists")
    if exists is None:
        state = "checked"
    elif exists:
        state = "found to exist"
    else:
        state = "reported as not existing"
    title = f"Root/jailbreak path check: {path}"
    description = f"The app checked for '{path}' via {api}; it was {state}{_suffix_for_check(p)}."
    return title, description, _severity_for_check(p)


def _describe_suspicious_property_check(p: dict[str, Any]) -> tuple[str, str, str]:
    key = p.get("key", "?")
    api = p.get("api", "?")
    value = p.get("value")
    title = f"System property check: {key}"
    description = f"The app read system property '{key}' via {api} (observed value: {value!r}){_suffix_for_check(p)}."
    return title, description, _severity_for_check(p)


def _describe_suspicious_package_check(p: dict[str, Any]) -> tuple[str, str, str]:
    api = p.get("api", "?")
    package = p.get("package")
    if package:
        title = f"PackageManager query: {package}"
        description = f"The app queried PackageManager for known root-management package '{package}' via {api}{_suffix_for_check(p)}."
    else:
        title = "PackageManager installed-app list filtered"
        description = f"The app enumerated installed packages via {api}; a known root-management package was present in the results{_suffix_for_check(p)}."
    return title, description, _severity_for_check(p)


def _describe_suspicious_native_check(p: dict[str, Any]) -> tuple[str, str, str]:
    api = p.get("api", "?")
    result = p.get("result")
    title = f"Root-detection library call: {api}"
    description = f"{api} was called and returned {result!r}{_suffix_for_check(p)}."
    return title, description, _severity_for_check(p)


def _describe_suspicious_setting_check(p: dict[str, Any]) -> tuple[str, str, str]:
    api = p.get("api", "?")
    key = p.get("key")
    if "error" in p:
        title = f"Developer-mode setting check: {api}"
        description = f"The app queried setting '{key}' via {api}; the setting was not present ({p['error']})."
        return title, description, "info"
    value = p.get("value")
    title = f"Developer-mode setting check: {key or api}"
    description = f"The app read '{key}' via {api} (value: {value!r}){_suffix_for_check(p)}."
    return title, description, _severity_for_check(p)


def _describe_process_exec(p: dict[str, Any]) -> tuple[str, str, str]:
    argv = p.get("argv") or []
    api = p.get("api", "?")
    command = " ".join(str(a) for a in argv) or "?"
    su_note = " (matches a known su/root-check pattern)" if p.get("su_check") else ""
    title = f"Process execution: {command.split(' ')[0]}"
    description = f"The app executed `{command}` via {api}{su_note}{_suffix_for_check(p)}."
    return title, description, _severity_for_check(p)


def _describe_build_fingerprint(p: dict[str, Any]) -> tuple[str, str, str]:
    title = "Device build fingerprint read"
    description = (
        f"android.os.Build reported fingerprint='{p.get('fingerprint')}', tags='{p.get('tags')}', "
        f"type='{p.get('type')}', model='{p.get('model')}'."
    )
    return title, description, "info"


# --------------------------------------------------------------------
# tls_inspector / flutter_tls
# --------------------------------------------------------------------


def _describe_tls_validation(p: dict[str, Any]) -> tuple[str, str, str]:
    api = p.get("api", "?")
    hostname = p.get("hostname")
    host_note = f" for host '{hostname}'" if hostname else ""
    title = f"TLS validation checkpoint: {api}"
    description = f"{api} was invoked{host_note}{_suffix_for_check(p)}."
    return title, description, _severity_for_check(p)


def _describe_flutter_engine_detected(p: dict[str, Any]) -> tuple[str, str, str]:
    modules = p.get("native_modules") or []
    module_names = ", ".join(m.get("name", "?") for m in modules) or "none found"
    markers = p.get("java_markers") or []
    title = "Flutter runtime detected"
    description = f"Native engine module(s): {module_names}. Java markers present: {', '.join(markers) or 'none'}."
    return title, description, "info"


def _describe_dart_runtime_detected(p: dict[str, Any]) -> tuple[str, str, str]:
    title = "Dart VM runtime confirmed"
    description = f"Dart_VersionString() in {p.get('module')} reported: {p.get('dart_version')}."
    return title, description, "info"


def _describe_native_tls_library_detected(p: dict[str, Any]) -> tuple[str, str, str]:
    symbols = p.get("symbols_found") or []
    version = p.get("library_version")
    title = f"Native TLS library identified: {p.get('module')}"
    description = f"{len(symbols)} known OpenSSL/BoringSSL export(s) found ({', '.join(symbols)})." + (
        f" Library version string: {version}." if version else ""
    )
    return title, description, "info"


def _describe_java_tls_path_detected(p: dict[str, Any]) -> tuple[str, str, str]:
    classes = p.get("classes_found") or []
    title = "Java-visible networking path also present"
    description = f"Classes found: {', '.join(classes)}. {p.get('note', '')}"
    return title, description, "info"


def _describe_hook_installed(p: dict[str, Any]) -> tuple[str, str, str]:
    title = f"Hook installed: {p.get('symbol')}"
    description = f"Strategy '{p.get('strategy')}' installed a hook on {p.get('symbol')} in {p.get('module')}."
    return title, description, "high"


def _describe_hook_installation_failed(p: dict[str, Any]) -> tuple[str, str, str]:
    title = f"Hook installation failed: {p.get('symbol')}"
    description = f"Strategy '{p.get('strategy')}' could not install a hook on {p.get('symbol')} (symbol not found)."
    return title, description, "low"


def _describe_fallback_path_selected(p: dict[str, Any]) -> tuple[str, str, str]:
    title = f"Fallback path: {p.get('reason')}"
    description = str(p.get("detail", ""))
    return title, description, "medium"


# --------------------------------------------------------------------
# anti_debug
# --------------------------------------------------------------------


def _describe_ptrace_call(p: dict[str, Any]) -> tuple[str, str, str]:
    is_traceme = p.get("isTraceme")
    title = "ptrace() self-debug-check" if is_traceme else "ptrace() call observed"
    description = f"ptrace() called with request={p.get('request')}{_suffix_for_check(p)}."
    return title, description, _severity_for_check(p) if is_traceme else "info"


def _describe_proc_probe(p: dict[str, Any]) -> tuple[str, str, str]:
    kind = p.get("kind", "?")
    title = f"/proc/self/{kind} opened"
    description = f"{p.get('api')} opened /proc/self/{kind} (fd={p.get('fd')})."
    return title, description, "info"


def _describe_anti_debug_bypass(p: dict[str, Any]) -> tuple[str, str, str]:
    if "kind" in p:
        title = f"TracerPid filtered from /proc/self/{p.get('kind')}"
        description = f"A read() of /proc/self/{p.get('kind')} (fd={p.get('fd')}) had TracerPid zeroed out before returning to the app."
        return title, description, "high"
    api = p.get("api", "?")
    title = f"Forced self-termination intercepted: {api}"
    description = f"{api}() was called by the app{_suffix_for_check(p)}."
    return title, description, _severity_for_check(p)


# --------------------------------------------------------------------
# recon
# --------------------------------------------------------------------


def _describe_suspicious_classes_found(p: dict[str, Any]) -> tuple[str, str, str]:
    frameworks = p.get("cross_platform_frameworks_detected") or {}
    title = "Loaded-class reconnaissance summary"
    description = (
        f"{p.get('own_classes_count', 0)} class(es) under the app's own package "
        f"({p.get('own_package')}); cross-platform framework(s) detected: {', '.join(frameworks.keys()) or 'none'}; "
        f"{len(p.get('known_rasp_sdk_matches') or [])} known RASP SDK match(es); "
        f"{p.get('keyword_matches_count', 0)} generic keyword match(es)."
    )
    return title, description, "info"


def _describe_reaction_point_hit(p: dict[str, Any]) -> tuple[str, str, str]:
    title = f"Reaction point fired: {p.get('label')}"
    description = f"{p.get('class')}.{p.get('method')} was called -- typically indicates the app is reacting to a positive detection (e.g. showing a block dialog)."
    return title, description, "high"


def _describe_unknown_class_shape(p: dict[str, Any]) -> tuple[str, str, str]:
    title = f"Unknown class inspected: {p.get('class')}"
    description = f"Reflection dump: {len(p.get('fields') or [])} field(s), {len(p.get('methods') or [])} method(s)."
    return title, description, "info"


def _describe_flutter_method_channel_call(p: dict[str, Any]) -> tuple[str, str, str]:
    method = p.get("invoked_method") or "?"
    title = f"Flutter MethodChannel call: {method}"
    description = f"'{method}' invoked on {p.get('handler_class')} (channel handler)."
    return title, description, "medium"


def _describe_flutter_method_channel_reply(p: dict[str, Any]) -> tuple[str, str, str]:
    title = f"Flutter MethodChannel reply: {p.get('method')}"
    description = f"{p.get('result_class')}.{p.get('method')}({', '.join(str(a) for a in (p.get('args') or []))})"
    return title, description, "info"


def _describe_library_method_trace(p: dict[str, Any]) -> tuple[str, str, str]:
    title = f"Traced library call: {p.get('class')}.{p.get('method')}"
    description = f"Returned {p.get('result')!r}{_suffix_for_check(p)}."
    return title, description, _severity_for_check(p)


# --------------------------------------------------------------------
# framework_detection
# --------------------------------------------------------------------


def _describe_framework_detection_started(_: dict[str, Any]) -> tuple[str, str, str]:
    return "Framework detection started", "The agent began evaluating which framework detectors matched this target.", "info"


def _describe_framework_confidence(p: dict[str, Any]) -> tuple[str, str, str]:
    title = f"Framework confidence: {p.get('framework')}"
    description = f"{p.get('framework')} scored {p.get('confidence')}/100."
    return title, description, "info"


def _describe_framework_evidence(p: dict[str, Any]) -> tuple[str, str, str]:
    title = f"Framework evidence: {p.get('framework')}"
    description = _join_evidence(p.get("evidence"))
    return title, description, "info"


def _describe_framework_detected(p: dict[str, Any]) -> tuple[str, str, str]:
    title = f"Framework detected: {p.get('framework')}"
    description = f"Confidence {p.get('confidence')}/100. Evidence: {_join_evidence(p.get('evidence'))}"
    return title, description, "high"


def _describe_framework_detection_finished(p: dict[str, Any]) -> tuple[str, str, str]:
    detected = p.get("detected") or []
    title = "Framework detection finished"
    description = f"Detected: {', '.join(detected) or 'none'}."
    return title, description, "info"


def _describe_automatic_modules_selected(p: dict[str, Any]) -> tuple[str, str, str]:
    modules = p.get("modules") or []
    title = "Modules automatically selected"
    description = f"For framework(s) {', '.join(p.get('frameworks') or []) or 'none'}: enabled {', '.join(modules)}."
    return title, description, "medium"


INTERPRETERS: dict[str, tuple[str, Describer]] = {
    "suspicious_path_check": ("root_jailbreak", _describe_suspicious_path_check),
    "suspicious_property_check": ("root_jailbreak", _describe_suspicious_property_check),
    "suspicious_package_check": ("root_jailbreak", _describe_suspicious_package_check),
    "suspicious_native_check": ("root_jailbreak", _describe_suspicious_native_check),
    "suspicious_setting_check": ("developer_mode", _describe_suspicious_setting_check),
    "process_exec": ("process_execution", _describe_process_exec),
    "build_fingerprint": ("device_fingerprint", _describe_build_fingerprint),
    "tls_validation": ("tls_pinning", _describe_tls_validation),
    "ptrace_call": ("anti_debugging", _describe_ptrace_call),
    "proc_probe": ("anti_debugging", _describe_proc_probe),
    "anti_debug_bypass": ("anti_debugging", _describe_anti_debug_bypass),
    "suspicious_classes_found": ("reconnaissance", _describe_suspicious_classes_found),
    "reaction_point_hit": ("reconnaissance", _describe_reaction_point_hit),
    "unknown_class_shape": ("reconnaissance", _describe_unknown_class_shape),
    "flutter_method_channel_call": ("reconnaissance", _describe_flutter_method_channel_call),
    "flutter_method_channel_reply": ("reconnaissance", _describe_flutter_method_channel_reply),
    "library_method_trace": ("reconnaissance", _describe_library_method_trace),
    "flutter_engine_detected": ("flutter_tls", _describe_flutter_engine_detected),
    "dart_runtime_detected": ("flutter_tls", _describe_dart_runtime_detected),
    "native_tls_library_detected": ("flutter_tls", _describe_native_tls_library_detected),
    "java_tls_path_detected": ("flutter_tls", _describe_java_tls_path_detected),
    "hook_installed": ("flutter_tls", _describe_hook_installed),
    "hook_installation_failed": ("flutter_tls", _describe_hook_installation_failed),
    "fallback_path_selected": ("flutter_tls", _describe_fallback_path_selected),
    "framework_detection_started": ("framework_detection", _describe_framework_detection_started),
    "framework_confidence": ("framework_detection", _describe_framework_confidence),
    "framework_evidence": ("framework_detection", _describe_framework_evidence),
    "framework_detected": ("framework_detection", _describe_framework_detected),
    "framework_detection_finished": ("framework_detection", _describe_framework_detection_finished),
    "automatic_modules_selected": ("framework_detection", _describe_automatic_modules_selected),
}


def _describe_generic(payload: dict[str, Any]) -> tuple[str, str, str]:
    details = ", ".join(f"{k}={v!r}" for k, v in payload.items()) or "no additional details"
    return "Event", details, "info"


def interpret(finding: Finding) -> InterpretedFinding:
    """Applies the registered interpreter for `finding.name`, or a generic fallback if none is registered."""
    category, describe = INTERPRETERS.get(finding.name, ("other", _describe_generic))
    try:
        title, description, severity = describe(finding.payload)
    except Exception:
        title, description, severity = _describe_generic(finding.payload)
    return InterpretedFinding(finding=finding, title=title, description=description, category=category, severity=severity)
