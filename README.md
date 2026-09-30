# burp-expedition

A Burp Suite extension (Montoya API) that adds an explicit-proxy **TCP/UDP relay**
with TLS MITM, full intercept-and-edit, match-and-replace, and a pluggable
dissector layer — the non-HTTP proxy capability Burp itself does not provide.

Burp's proxy is scoped to HTTP(S)/WebSocket. This embeds its own Netty-based
proxy engine and surfaces it through a Burp suite tab, so you can intercept and
rewrite arbitrary TCP and UDP traffic from inside Burp.

## Features

**Proxy engine**
- **TCP, UDP, and SOCKS5 listeners** — explicit-proxy (bind → fixed upstream), or a SOCKS5
  listener that relays to each client-negotiated destination.
- **Upstream proxy chaining** — route a listener's upstream leg through an outbound SOCKS5 proxy.
- **TLS MITM & STARTTLS** — terminate client TLS with per-host leaf certs, or detect and
  upgrade a plaintext→TLS negotiation (SMTP / IMAP / POP3 / PostgreSQL). Client-certificate
  (mutual-TLS) support for upstreams that require one.
- **Intercept and edit** — hold, edit (hex / string / decoded view), forward, or drop live.
- **Match and replace** — literal-bytes / literal-string / regex rules, applied to the raw
  bytes or to a dissector's decoded view (re-encoded with length/framing fixed).

**Protocol dissectors** — pluggable SPI, auto-selected per message:
hex/string, line/text, Redis (RESP), **Protobuf**, **DNS**, **MQTT**, **PostgreSQL**,
**MySQL**, **MongoDB**, **WebSocket**, **Modbus/TCP**, **DNP3**.

**Workflow**
- **History** — connection/message log with connection replay, flow tagging, and JSON
  session save / restore / export.
- **Fuzzer** — replay a captured payload with mutations over TCP/UDP.
- **Control API** — a loopback JSON REST API (`:18112`) to drive listeners, history, the
  Repeater, intercept, and match-and-replace from automation (see below); exposed in
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

**By default it just works:** on first load the extension generates a unique CA under
`~/.expedition/` (`EXPEDITION_CA_DIR` to relocate, `EXPEDITION_AUTOCA_DISABLE=1` to turn
off) and uses it for TLS MITM / STARTTLS. Install `~/.expedition/expedition-ca.crt` in
whatever client you're testing so it trusts the minted leaf certs. The CA private key
never leaves that folder and is never committed.

**To reuse Burp's own CA instead** (so devices already trusting Burp need no new cert) —
the Montoya API can't read Burp's CA key, so export it once:

1. Burp → **Proxy** → **Proxy settings** → **Import / export CA certificate** →
   export as **PKCS#12** (certificate **and** private key).
2. In the **Listeners** tab, **Configure CA Keystore…**, select that `.p12` and
   enter its password (this replaces the auto-generated CA).
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
| `GET /listeners` · `POST /listeners` · `DELETE /listeners/{name}` | list / add+start / stop a listener¹ |
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

¹ `POST /listeners` also accepts `"protocol":"socks5"`, `"tls":"mitm"|"starttls"`,
`"upstream_proxy":"host:port"`, and `"client_cert":"/path.p12"` + `"client_cert_password"`.

In Praetor these are the `tcp_proxy_*`, `tcp_repeat`, and `tcp_match_replace_*` MCP tools.

## Stack

Kotlin (JVM 17), Gradle Kotlin DSL, Netty, Bouncy Castle, Montoya API,
JUnit 5. Exact versions are in [`build.gradle.kts`](build.gradle.kts).

## Scope

Explicit-proxy only — clients are pointed at a listener directly or routed via SOCKS5;
no transparent/OS-level redirection. UDP listeners are plaintext (no TLS/STARTTLS). The
dissectors decode the common cases per protocol; anything beyond their documented editable
fields falls back to hex. Pure-JVM (Nio transport only), so it runs the same on Linux,
macOS, and Windows.

## License

[Apache-2.0](LICENSE).
