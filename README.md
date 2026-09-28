# burp-expedition

A Burp Suite extension (Montoya API) that adds an explicit-proxy **TCP/UDP relay**
with TLS MITM, full intercept-and-edit, match-and-replace, and a pluggable
dissector layer — the non-HTTP proxy capability Burp itself does not provide.

Burp's proxy is scoped to HTTP(S)/WebSocket. This embeds its own Netty-based
proxy engine and surfaces it through a Burp suite tab, so you can intercept and
rewrite arbitrary TCP and UDP traffic from inside Burp.

## Features

- **TCP and UDP relay** — explicit-proxy listeners (bind host/port → upstream host/port).
- **TLS MITM** — terminates client TLS with per-host leaf certificates signed by
  your exported Burp CA, mirroring Burp's own HTTP proxy trust model.
- **Intercept and edit** — hold, edit (hex/string), forward, or drop messages live.
- **Match and replace** — ordered literal-bytes / literal-string / regex rules.
- **History** — connection and message log with connection replay.
- **Dissector SPI** — a pluggable rendering/parsing interface (hex/string default);
  the extension point for protocol-specific decoders.

## Build

Requires JDK 17+.

```sh
./gradlew shadowJar
```

Produces the extension at `build/libs/burp-expedition-0.1.0.jar`. Bundled
dependencies (Netty, Bouncy Castle) are relocated under `expedition.shaded.*`;
the Montoya API is `compileOnly` and supplied by Burp at runtime.

## Install

Burp → **Extensions** → **Add** → Extension type: **Java** → select the built jar.
An **Expedition** tab appears with four sub-tabs: Listeners, Intercept, History,
Match & Replace.

## TLS MITM setup

The Montoya API exposes no way to read Burp's CA key, so TLS termination uses a
CA keystore you export once:

1. Burp → **Proxy** → **Proxy settings** → **Import / export CA certificate** →
   export as **PKCS#12** (certificate **and** private key).
2. In the **Listeners** tab, **Configure CA Keystore…**, select that `.p12` and
   enter its password.
3. Add a listener with TLS mode **MITM**. Clients that already trust Burp's CA
   need no new certificate.

## Stack

Kotlin (JVM 17), Gradle Kotlin DSL, Netty, Bouncy Castle, Montoya API,
JUnit 5. Exact versions are in [`build.gradle.kts`](build.gradle.kts).

## Scope

v1 is explicit-proxy only (no transparent/OS-level redirection). UDP listeners
are plaintext (no TLS). Only the hex/string dissector ships; the SPI is the seam
for protocol-specific ones.

## License

[Apache-2.0](LICENSE).
