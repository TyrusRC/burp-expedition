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
- **Control API** — a loopback JSON REST API (`:18112`) to drive listeners, history,
  the Repeater, and match-and-replace from automation (see below); exposed in
  Praetor as the `tcp_proxy_*` MCP tools.

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

## Control API (loopback, for automation / Praetor MCP)

The extension serves a small JSON REST API on **`127.0.0.1:18112`** so an external
client — the [Praetor](https://github.com/TyrusRC/praetor) MCP server — can drive
the proxy programmatically: manage listeners, read captured connections/messages
as evidence, run the Repeater, and manage match-and-replace rules.

- **Security:** loopback-only by default; every request's `Host` header is checked
  against literal loopback (or the configured bind host) — DNS-rebinding safe,
  never resolves a hostname. The API can start proxies and send arbitrary bytes,
  so it must never be exposed to an untrusted network.
- **Env:** `EXPEDITION_API_PORT` (default `18112`); `EXPEDITION_API_DISABLE=1` to
  turn it off; `EXPEDITION_API_HOST` to bind a non-loopback interface **only** when
  the client is off-host (NAT-mode WSL reaching Burp on the Windows IP) — set it to
  the reachable IP, not `0.0.0.0`; a warning is logged when bound beyond loopback.

| Method + path | Purpose |
|---|---|
| `GET /status` | version, running listeners, connection/message counts |
| `GET /listeners` · `POST /listeners` · `DELETE /listeners/{name}` | list / add+start / stop a listener |
| `GET /connections` | captured connection summaries |
| `GET /connections/{id}/messages` · `GET /messages?limit=N` | captured messages (hex + ASCII preview) |
| `POST /repeat` | Repeater — send a raw TCP/UDP payload, read the response |
| `GET /matchreplace` · `POST /matchreplace` · `DELETE /matchreplace/{id}` | list / add / remove rules |
| `GET /intercept` · `POST /intercept/enable` | held-message queue + toggle live intercept |
| `POST /intercept/{id}/forward` · `POST /intercept/{id}/drop` | forward (edited or unchanged) / drop a held message |

Example:

```sh
curl -s 127.0.0.1:18112/status
curl -s -XPOST 127.0.0.1:18112/listeners \
  -d '{"name":"redis","protocol":"tcp","bind_port":16379,"upstream_host":"10.0.0.5","upstream_port":6379}'
curl -s -XPOST 127.0.0.1:18112/repeat \
  -d '{"protocol":"tcp","host":"10.0.0.5","port":6379,"text":"PING\r\n"}'
```

In Praetor these are the `tcp_proxy_*`, `tcp_repeat`, and `tcp_match_replace_*` MCP tools.

## Stack

Kotlin (JVM 17), Gradle Kotlin DSL, Netty, Bouncy Castle, Montoya API,
JUnit 5. Exact versions are in [`build.gradle.kts`](build.gradle.kts).

## Scope

v1 is explicit-proxy only (no transparent/OS-level redirection). UDP listeners
are plaintext (no TLS). Only the hex/string dissector ships; the SPI is the seam
for protocol-specific ones.

## License

[Apache-2.0](LICENSE).
