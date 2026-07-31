// Module 3: TLS/Network Inspection & SSL Pinning Bypass.
//
// Every hook here always emits a `tls_validation` event, whether or
// not bypass is enabled -- so this module is safe to run purely as a
// handshake-observability tool (config.bypass left false, the default)
// if that's all a given engagement calls for.
//
// Bypass surfaces, gated by config.bypass:
//   - Android: substitutes the app's own TrustManager(s) at the one
//     guaranteed choke point (SSLContext.init), patches OkHttp's
//     CertificatePinner, and neutralizes WebViewClient's SSL-error handling.
//   - iOS: forces SecTrustEvaluate(WithError) to report success, and
//     (best-effort -- see installNSURLSessionChallengeBypass) answers
//     NSURLSession's auth-challenge delegate callback directly.
//   - Native (OpenSSL/BoringSSL): flips SSL_CTX's verify mode to
//     SSL_VERIFY_NONE, forces SSL_get_verify_result to report X509_V_OK,
//     and substitutes BoringSSL's custom_verify callback -- for apps that
//     talk to OpenSSL/BoringSSL directly instead of through the platform
//     TLS stack (common for native/cross-platform/game engines).

import { log, event } from "../common/rpc.js";
import { attachSafe, resolveExport, isAndroid, isIOS } from "../common/native_utils.js";

const MODULE_NAME = "tls_inspector";

let bypassEnabled = false;

function reportPinning(api, extra = {}) {
    event(MODULE_NAME, "tls_validation", { api, bypassed: bypassEnabled, ...extra });
}

// --------------------------------------------------------------------
// Native (OpenSSL / BoringSSL) hooks
// --------------------------------------------------------------------

let sslGetServername; // undefined = not yet resolved, false = resolved-and-absent

function getSslGetServername() {
    if (sslGetServername !== undefined) return sslGetServername;
    const resolved = resolveExport([[null, "SSL_get_servername"]]);
    if (resolved === null) {
        sslGetServername = false;
        return sslGetServername;
    }
    sslGetServername = new NativeFunction(resolved.address, "pointer", ["pointer", "int"]);
    return sslGetServername;
}

/** Best-effort SNI hostname lookup for a live `SSL *` -- returns null if unavailable. */
function readServerName(sslPtr) {
    const fn = getSslGetServername();
    if (!fn) return null;
    try {
        const TLSEXT_NAMETYPE_host_name = 0;
        const namePtr = fn(sslPtr, TLSEXT_NAMETYPE_host_name);
        return namePtr.isNull() ? null : namePtr.readCString();
    } catch (e) {
        return null;
    }
}

function hookSslCtxSetVerify() {
    const resolved = resolveExport([[null, "SSL_CTX_set_verify"]]);
    if (resolved === null) {
        log(MODULE_NAME, "debug", "SSL_CTX_set_verify: no matching export found");
        return;
    }
    attachSafe(MODULE_NAME, resolved.address, {
        onEnter(args) {
            const requestedMode = args[1].toInt32();
            reportPinning("SSL_CTX_set_verify", {
                symbol: `${resolved.moduleName}!${resolved.symbolName}`,
                requestedMode,
            });
            if (bypassEnabled) {
                args[1] = ptr(0); // SSL_VERIFY_NONE -- skip verification entirely
            }
        },
    });
    log(MODULE_NAME, "debug", `Hooked SSL_CTX_set_verify -> ${resolved.moduleName}!${resolved.symbolName}`);
}

function hookSslGetVerifyResult() {
    const resolved = resolveExport([[null, "SSL_get_verify_result"]]);
    if (resolved === null) {
        log(MODULE_NAME, "debug", "SSL_get_verify_result: no matching export found");
        return;
    }
    attachSafe(MODULE_NAME, resolved.address, {
        onEnter(args) {
            this.ssl = args[0];
        },
        onLeave(retval) {
            const originalResult = retval.toInt32();
            if (originalResult === 0) return; // X509_V_OK already -- nothing to report or bypass
            const bypassed = bypassEnabled;
            reportPinning("SSL_get_verify_result", {
                symbol: `${resolved.moduleName}!${resolved.symbolName}`,
                originalResult,
                hostname: readServerName(this.ssl),
                bypassed,
            });
            if (bypassed) {
                retval.replace(0); // X509_V_OK
            }
        },
    });
    log(MODULE_NAME, "debug", `Hooked SSL_get_verify_result -> ${resolved.moduleName}!${resolved.symbolName}`);
}

function hookSslSetCustomVerify() {
    const resolved = resolveExport([[null, "SSL_set_custom_verify"], [null, "SSL_CTX_set_custom_verify"]]);
    if (resolved === null) {
        log(MODULE_NAME, "debug", "SSL_set_custom_verify: no matching export found");
        return;
    }

    // BoringSSL's custom_verify callback is arbitrary app-native code --
    // some apps pin certs at exactly this layer, entirely below anything
    // the Java/platform TLS stack sees. The only reliable way to
    // neutralize it is to never call it, so when bypass is enabled we
    // substitute the callback argument with one that always
    // reports ssl_verify_ok (0). Declared once here (not inside onEnter) so
    // the NativeCallback stays reachable for as long as the hook is live --
    // a NativeCallback that gets GC'd while native code can still invoke it
    // is a use-after-free.
    const alwaysOk = new NativeCallback(() => 0, "int", ["pointer", "pointer"]);

    attachSafe(MODULE_NAME, resolved.address, {
        onEnter(args) {
            reportPinning("SSL_set_custom_verify", { symbol: `${resolved.moduleName}!${resolved.symbolName}` });
            if (bypassEnabled) {
                args[2] = alwaysOk;
            }
        },
    });
    log(MODULE_NAME, "debug", `Hooked SSL_set_custom_verify -> ${resolved.moduleName}!${resolved.symbolName}`);
}

function hookSecTrustEvaluateWithError() {
    const resolved = resolveExport([[null, "SecTrustEvaluateWithError"]]);
    if (resolved === null) {
        log(MODULE_NAME, "debug", "SecTrustEvaluateWithError: no matching export found");
        return;
    }
    attachSafe(MODULE_NAME, resolved.address, {
        onLeave(retval) {
            const trusted = retval.toInt32() !== 0;
            reportPinning("SecTrustEvaluateWithError", { trusted, bypassed: bypassEnabled && !trusted });
            if (bypassEnabled && !trusted) {
                retval.replace(1); // Boolean true
            }
        },
    });
    log(MODULE_NAME, "debug", `Hooked SecTrustEvaluateWithError -> ${resolved.moduleName}!${resolved.symbolName}`);
}

function hookSecTrustEvaluate() {
    const resolved = resolveExport([[null, "SecTrustEvaluate"]]);
    if (resolved === null) {
        log(MODULE_NAME, "debug", "SecTrustEvaluate: no matching export found");
        return;
    }
    attachSafe(MODULE_NAME, resolved.address, {
        onEnter(args) {
            this.resultPtr = args[1]; // SecTrustResultType * (CFIndex-sized out-param)
        },
        onLeave(retval) {
            reportPinning("SecTrustEvaluate", { status: retval.toInt32(), bypassed: bypassEnabled });
            if (!bypassEnabled) return;
            try {
                if (!this.resultPtr.isNull()) {
                    this.resultPtr.writePointer(ptr(1)); // kSecTrustResultProceed
                }
            } catch (e) {
                // best-effort only
            }
            retval.replace(0); // errSecSuccess
        },
    });
    log(MODULE_NAME, "debug", `Hooked SecTrustEvaluate -> ${resolved.moduleName}!${resolved.symbolName}`);
}

function installNativeTlsHooks() {
    hookSslCtxSetVerify();
    hookSslGetVerifyResult();
    hookSslSetCustomVerify();
    hookSecTrustEvaluateWithError();
    hookSecTrustEvaluate();
}

// --------------------------------------------------------------------
// Android (Java) hooks
// --------------------------------------------------------------------

function installTrustManagerBypass() {
    try {
        const X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
        const SSLContext = Java.use("javax.net.ssl.SSLContext");

        // X509TrustManager is an interface -- Frida can only hook concrete,
        // already-loaded implementations, and apps frequently build their
        // own (sometimes anonymous/obfuscated) TrustManager classes. Rather
        // than chase every possible implementer, we intercept the one
        // guaranteed choke point: SSLContext.init() is how every custom
        // TrustManager gets wired in, regardless of what it looks like.
        const TrustAllManager = Java.registerClass({
            name: "com.shieldbreaker.tls.TrustAllManager",
            implements: [X509TrustManager],
            methods: {
                checkClientTrusted(chain, authType) {},
                checkServerTrusted(chain, authType) {},
                getAcceptedIssuers() {
                    return [];
                },
            },
        });

        SSLContext.init.overload(
            "[Ljavax.net.ssl.KeyManager;", "[Ljavax.net.ssl.TrustManager;", "java.security.SecureRandom"
        ).implementation = function (keyManagers, trustManagers, secureRandom) {
            reportPinning("SSLContext.init");
            const effectiveTrustManagers = bypassEnabled
                ? Java.array("javax.net.ssl.TrustManager", [TrustAllManager.$new()])
                : trustManagers;
            return this.init(keyManagers, effectiveTrustManagers, secureRandom);
        };
    } catch (e) {
        log(MODULE_NAME, "error", `Failed to install TrustManager bypass: ${e.stack || e}`);
    }
}

function installOkHttpCertificatePinnerBypass() {
    try {
        const CertificatePinner = Java.use("okhttp3.CertificatePinner");

        // `check` covers OkHttp 3.x/4.x's public overloads; `check$okhttp` is
        // the Kotlin-mangled internal method some 4.x releases call directly,
        // bypassing the public wrapper. Iterating .overloads (rather than
        // hardcoding one signature) keeps this working across OkHttp versions.
        ["check", "check$okhttp"].forEach((methodName) => {
            try {
                CertificatePinner[methodName].overloads.forEach((overload) => {
                    overload.implementation = function (...args) {
                        const hostname = typeof args[0] === "string" ? args[0] : undefined;
                        reportPinning(`OkHttp.CertificatePinner.${methodName}`, { hostname });
                        if (!bypassEnabled) {
                            return this[methodName](...args);
                        }
                        // check()/check$okhttp() are void -- simply not
                        // throwing is what tells OkHttp the pin passed.
                    };
                });
            } catch (e) {
                log(MODULE_NAME, "debug", `okhttp3.CertificatePinner.${methodName} not present on this build`);
            }
        });
    } catch (e) {
        log(MODULE_NAME, "debug", "okhttp3.CertificatePinner not present (app may not use OkHttp)");
    }
}

function installWebViewSslErrorBypass() {
    const patchedClasses = new Set();

    const patchClass = (className) => {
        if (patchedClasses.has(className)) return;
        try {
            const klass = Java.use(className);
            klass.onReceivedSslError.overload(
                "android.webkit.WebView", "android.webkit.SslErrorHandler", "android.net.http.SslError"
            ).implementation = function (view, handler, error) {
                reportPinning("WebViewClient.onReceivedSslError", { class: className, url: error.getUrl() });
                if (bypassEnabled) {
                    handler.proceed();
                } else {
                    this.onReceivedSslError(view, handler, error);
                }
            };
            patchedClasses.add(className);
        } catch (e) {
            // className doesn't override this overload -- not an error, just not applicable
        }
    };

    patchClass("android.webkit.WebViewClient");

    // App-defined subclasses override onReceivedSslError themselves, so the
    // base-class patch alone misses them unless they call super() -- find
    // and patch those too.
    Java.enumerateLoadedClasses({
        onMatch(className) {
            if (className !== "android.webkit.WebViewClient" && className.toLowerCase().includes("webviewclient")) {
                patchClass(className);
            }
        },
        onComplete() {
            log(MODULE_NAME, "debug", `WebViewClient SSL-error patch installed on ${patchedClasses.size} class(es)`);
        },
    });
}

function installAndroidHooks() {
    Java.perform(() => {
        installTrustManagerBypass();
        installOkHttpCertificatePinnerBypass();
        installWebViewSslErrorBypass();
    });
}

// --------------------------------------------------------------------
// iOS hooks
// --------------------------------------------------------------------

/**
 * Best-effort: answers NSURLSessionDelegate's auth-challenge callback
 * directly for every loaded class implementing it. This is the most
 * version/architecture-fragile hook in the module -- block-calling
 * conventions have shifted across iOS releases, which is why even
 * production unpinning tools treat this exact hook as inherently
 * best-effort. Only installed when bypass is enabled: with bypass off
 * there is nothing safe to do here (letting the original run is already
 * the default, since we haven't touched anything), and wrapping the
 * call without fully replacing it risks the app's completionHandler
 * being invoked twice (a hard crash on iOS).
 */
function installNSURLSessionChallengeBypass() {
    if (!bypassEnabled) return;

    const selector = "- URLSession:didReceiveChallenge:completionHandler:";
    let patchedCount = 0;

    for (const className in ObjC.classes) {
        if (!Object.prototype.hasOwnProperty.call(ObjC.classes, className)) continue;
        const clazz = ObjC.classes[className];
        const method = clazz[selector];
        if (!method) continue;

        try {
            Interceptor.replace(method.implementation, new NativeCallback(
                (self, cmd, session, challenge, completionHandlerPtr) => {
                    try {
                        const challengeObj = new ObjC.Object(challenge);
                        const protectionSpace = challengeObj.protectionSpace();
                        const trust = protectionSpace.serverTrust();
                        const credential = ObjC.classes.NSURLCredential["+ credentialForTrust:"](trust);
                        const completionHandler = new ObjC.Block(completionHandlerPtr);
                        const invoke = completionHandler.implementation;
                        invoke(0 /* NSURLSessionAuthChallengeUseCredential */, credential);
                        reportPinning("NSURLSessionDelegate.didReceiveChallenge", {
                            class: className,
                            hostname: protectionSpace.host().toString(),
                            port: protectionSpace.port(),
                        });
                    } catch (e) {
                        log(MODULE_NAME, "error", `NSURLSession challenge bypass failed for ${className}: ${e.stack || e}`);
                    }
                },
                "void", ["pointer", "pointer", "pointer", "pointer", "pointer"]
            ));
            patchedCount += 1;
        } catch (e) {
            // Some classes may not be hookable this way -- skip and continue.
        }
    }
    log(MODULE_NAME, "debug", `Patched ${patchedCount} class(es) implementing ${selector}`);
}

function installIOSHooks() {
    installNSURLSessionChallengeBypass();
}

// --------------------------------------------------------------------
// Entry point (called by agents/loader.js)
// --------------------------------------------------------------------

export function init(config = {}) {
    bypassEnabled = Boolean(config.bypass);

    installNativeTlsHooks();

    if (isAndroid()) {
        installAndroidHooks();
    }
    if (isIOS()) {
        installIOSHooks();
    }

    log(MODULE_NAME, "info", "tls_inspector hooks installed", {
        android: isAndroid(),
        ios: isIOS(),
        bypass: bypassEnabled,
    });
}
