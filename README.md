# Burp Expedition

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Kotlin](https://img.shields.io/badge/Kotlin-2.0-7F52FF.svg)](build.gradle.kts)
[![JDK 17+](https://img.shields.io/badge/JDK-17%2B-ED8B00.svg)](#building)
[![Burp Montoya API](https://img.shields.io/badge/Burp-Montoya%20API-FF6633.svg)](https://portswigger.net/burp/documentation/desktop/extensions)

> A Burp Suite extension that adds a full **TCP/UDP relay** — TLS MITM, intercept-and-edit,
> match-and-replace, protocol dissectors, DNS redirection and scripting — the non-HTTP proxy
> capability Burp itself does not provide.

Burp's proxy is scoped to HTTP(S)/WebSocket. Expedition embeds its own Netty-based proxy
engine and surfaces it through a Burp suite tab, so you can intercept and rewrite arbitrary
TCP and UDP traffic — thick clients, mobile back-ends, databases, IoT and binary protocols —
from inside Burp.

## Contents

- [Features](#features)
- [Installing](#installing)
- [Building](#building)
- [Quick start](#quick-start)
- [TLS MITM setup](#tls-mitm-setup)
- [DNS redirector](#dns-redirector)
- [Scripting](#scripting)
- [HTTP rules](#http-rules)
- [Using Expedition rules on Burp Proxy traffic (Burp → SOCKS chain)](#using-expedition-rules-on-burp-proxy-traffic-burp--socks-chain)
- [Control API](#control-api)
- [Architecture](#architecture)
- [Scope & limitations](#scope--limitations)
- [Known limitations vs HTTP Toolkit Pro](#known-limitations-vs-http-toolkit-pro)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [License](#license)

## Features

**Proxy engine**
- **TCP, UDP and SOCKS5 listeners** — explicit-proxy (bind → fixed upstream), or a SOCKS5
  listener that relays to each client-negotiated destination.
- **Upstream proxy chaining** — route a listener's upstream leg through an outbound SOCKS5 proxy.
- **TLS MITM & STARTTLS** — terminate client TLS with per-host leaf certs, or detect and upgrade
  a plaintext→TLS negotiation (SMTP / IMAP / POP3 / PostgreSQL). Client-certificate (mutual-TLS)
  support for upstreams that require one.
- **Intercept and edit** — hold, edit (hex / string / decoded view), forward or drop live traffic.
- **Match and replace** — literal-bytes / literal-string / regex rules, applied to the raw bytes
  or to a dissector's decoded view (re-encoded with length/framing fixed). Regex is validated at
  rule-creation time and guarded against catastrophic backtracking (ReDoS).

**Protocol dissectors** — pluggable SPI, auto-selected per message by signature specificity, with
a hex/string fallback. Decode (and, where framing allows, edit) of:

| | |
|---|---|
| **Web / RPC** | HTTP/2, gRPC (length-prefixed), Protobuf, WebSocket (incl. nested Protobuf), TLS (ClientHello/ServerHello — SNI/ALPN/version/ciphers) |
| **Data stores** | Redis (RESP), PostgreSQL, MySQL, MongoDB |
| **Messaging** | AMQP, Kafka, MQTT |
| **Infra / directory** | DNS, LDAP, SMB2, STUN/TURN (RFC 5389), QUIC (Initial/Handshake SNI) |
| **Industrial** | Modbus/TCP, DNP3 |

**Workflow & tooling**
- **History** — connection/message log with connection replay, flow tagging, and JSON session
  save / restore / export.
- **Fuzzer** — replay a captured payload with mutations over TCP/UDP.
- **DNS redirector** — a spoofing resolver that answers chosen hosts with an attacker IP to pull a
  target's traffic into the proxy. See [DNS redirector](#dns-redirector).
- **Scripting** — an optional JSR-223 hook that transforms every forwarded message. See
  [Scripting](#scripting).
- **Control API** — an opt-in loopback JSON REST API for automation / MCP. See [Control API](#control-api).

## Installing

1. [Build the jar](#building), or grab a prebuilt `burp-expedition-<version>.jar`.
2. In Burp: **Extensions → Add → Extension type: Java →** select the jar.
3. It loads as **"Burp Expedition"** and adds an **Expedition** suite tab with sub-tabs:
   **Listeners, Intercept, History, Match & Replace, Scripting, DNS**. TLS works out of the box
   via an auto-generated CA (see [TLS MITM setup](#tls-mitm-setup)).

To update: rebuild, then in **Extensions** untick and re-tick the extension (or remove and re-add)
to reload the new jar.

## Building

Requires a **JDK 17 or newer** on `PATH` (JDK 21 is fine — the build targets JVM 17 bytecode
regardless, so it loads in Burp's bundled JRE). No separate Gradle install is needed; the wrapper
fetches everything.

```sh
# macOS / Linux
./gradlew shadowJar

# Windows (PowerShell / cmd)
gradlew.bat shadowJar
```

This produces a self-contained extension at `build/libs/burp-expedition-<version>.jar`. Bundled
dependencies (Netty, Bouncy Castle) are relocated under `expedition.shaded.*`; the Montoya API is
`compileOnly` and supplied by Burp at runtime. Pure-JVM (Nio transport), so the same jar runs on
macOS, Linux and Windows.

Run the test suite with `./gradlew test`.

## Quick start

1. Open the **Expedition** tab → **Listeners** → add a listener: a bind port and the fixed
   upstream `host:port` (pick TCP, UDP or SOCKS5; optionally TLS **MITM** or **STARTTLS**).
2. Point your client at the bind port (or at the SOCKS5 listener).
3. Watch traffic in **History**; flip on **Intercept** to hold/edit/drop live; add **Match &
   Replace** rules to rewrite on the fly.

## TLS MITM setup

**By default it just works:** on first load the extension generates a unique CA under
`~/.expedition/` (`EXPEDITION_CA_DIR` to relocate, `EXPEDITION_AUTOCA_DISABLE=1` to turn off) and
uses it for TLS MITM / STARTTLS. Install `~/.expedition/expedition-ca.crt` in whatever client
you're testing so it trusts the minted leaf certs. The CA private key never leaves that folder and
is never committed.

**To reuse Burp's own CA instead** (so devices already trusting Burp need no new cert) — the
Montoya API can't read Burp's CA key, so export it once:

1. Burp → **Proxy → Proxy settings → Import / export CA certificate →** export as **PKCS#12**
   (certificate **and** private key).
2. In the **Listeners** tab, **Configure CA Keystore…**, select that `.p12` and enter its password
   (this replaces the auto-generated CA).
3. Add a listener with TLS mode **MITM**. Clients that already trust Burp's CA need no new cert.

## DNS redirector

A spoofing DNS resolver (the **DNS** tab, or the `/dns` API) that answers chosen hostnames with an
attacker-controlled IP — the standard way to pull a thick client's or mobile app's traffic into the
proxy when it ignores proxy settings.

- Ordered, case-insensitive rules (`host  ip` per line); `*` matches everything and `*.suffix`
  matches a domain and its subdomains.
- An optional catch-all **default IP** for unmatched names; with no default, unmatched names get
  `NXDOMAIN`.
- Answers **A** and **AAAA**; a query whose type doesn't match the configured IP family returns
  `NOERROR`/no-answer rather than a wrong-family record.
- Binding port **53 requires root/admin**; use any other port and point the target's resolver at it.

## Scripting

An optional **JSR-223** hook (the **Scripting** tab, or the `/script` API) runs one operator script
against every forwarded message, after match-and-replace. The script is evaluated with the bindings
`bytes` (`byte[]`), `direction` (`String`) and `connectionId` (`long`); return a `byte[]`/`String`
to replace the message, or `null` to leave it unchanged.

- **Engine-agnostic:** no interpreter is bundled. It uses whatever JSR-223 engine the host provides
  (Expedition does not bundle or verify one — add a JSR-223 engine jar to Burp's classpath if none
  is found) and is a safe no-op when none is present.
- **Fail-safe:** a compile error is rejected when you apply the script; a runtime error forwards the
  original bytes unchanged and is surfaced, never dropping or corrupting traffic.
- **Full JVM privileges, no sandbox** — by design, the same trust level as any Burp extension.
  Only an operator who already controls the Burp process can set a script (local UI / loopback API).
- **Opening a project never runs code or binds sockets:** a script saved in a Burp project is
  restored into the Scripting editor **unapplied** (review it, then click Apply), and saved
  listeners come back **stopped** (select them and click Start).
  Never wire script-setting to untrusted input.

## HTTP rules

A declarative rules engine (**Rules** tab, or `/rules` in the Control API) for HTTP/1.x carried
over TCP listeners (plaintext or decrypted by TLS MITM). Rules are evaluated in order; every
non-null matcher field must match: `method` (`GET|POST`), `host` glob, `port`, `path` glob,
`pathRegex` (path+query), `headers` (name + optional value regex), `bodyRegex`, `listener`,
`connectionId`, and `direction` (`request`, or `response` with `status`). Actions run in order:
`mock` (answered locally — the request is **never** sent upstream), `transformRequest` /
`transformResponse` (set/remove headers, regex body or URL rewrite on the de-chunked, decoded body,
status), `redirect` (send to another `http(s)://host:port`), `delay` (`ms`, `jitterMs`), `timeout`
(never answer), `close`, `reset` (TCP RST), `passthrough`, `breakpoint` (hold in Intercept even
while it is off) and `webhook` (POST a JSON summary; with `respond` its JSON reply becomes the
response; inert until `POST /rules/webhooks {"enabled":true}`). A rule with only non-terminal
actions (transform, delay, breakpoint) lets the next matching rule run; `times` limits how many
messages a rule handles. Keep-alive, pipelining and chunked bodies are handled and responses
always reach the client in request order; after `101`/`CONNECT` or on non-HTTP bytes the
connection reverts to raw relay. With no enabled rule, traffic is relayed exactly as before.
Rules are saved with the rest of the configuration.

```sh
curl -s -XPOST 127.0.0.1:18112/rules -d '{"name":"mock login",
  "match":{"method":"POST","host":"*.example.com","path":"/api/login","bodyRegex":"user=admin"},
  "actions":[{"type":"delay","ms":300},
             {"type":"mock","status":200,"headers":{"Content-Type":"application/json"},"body":"{\"ok\":true}"}]}'
curl -s 127.0.0.1:18112/rules                                   # list (with hit counts)
curl -s -XPOST 127.0.0.1:18112/rules/3/enable -d '{"enabled":false}'
curl -s -XPOST 127.0.0.1:18112/rules/reorder -d '{"ids":[3,1,2]}'
curl -s -XPOST 127.0.0.1:18112/rules/from-message -d '{"connection_id":12,"message_id":40}'  # mock from captured traffic
```

Other routes: `GET|PUT|DELETE /rules/{id}`, `POST /rules/{id}/move {"to":n}`, `DELETE /rules`.
Limitations: HTTP/1.x only, not applied to UDP or TLS-passthrough traffic, and bodies over 16 MiB are
streamed without evaluation. While a rule is enabled for a listener, MITM offers only `http/1.1` to
the client so browsers fall back to HTTP/1.1 and rules run; a client that speaks only HTTP/2 (e.g.
gRPC) still passes through as bytes and the History shows a `RULES BYPASSED: HTTP/2` note. When a
mock or redirect rule is active the upstream is dialled lazily (only when a request actually needs
it), so a mock can answer for a host that does not exist; a request that does need an unreachable
upstream gets a `502` and the connection closes, and requests pipelined behind it are lost. A
listener with no active rule dials the upstream when the client connects, as before.

## Using Expedition rules on Burp Proxy traffic (Burp → SOCKS chain)

Montoya handlers cannot return synthetic responses, so rules (mock / delay / timeout / RST /
redirect / transform) cannot run inside a Burp handler. Instead, chain Burp's upstream SOCKS proxy
into an Expedition SOCKS5 listener with TLS MITM: `client → Burp Proxy → Expedition SOCKS5 → server`.
The Setup tab target **`burp-chain`** (also `GET /setup/burp-chain`) generates these values.

1. **Create the listener** (Listeners tab: protocol SOCKS5, TLS MITM; or the control API, started with
   `EXPEDITION_API_ENABLE=1`):
   ```
   curl -s -X POST http://127.0.0.1:18112/listeners \
     -H "Authorization: Bearer $(cat ~/.expedition/api-token)" -H 'Content-Type: application/json' \
     -d '{"name":"burp-chain","protocol":"socks5","bind_host":"127.0.0.1","bind_port":1080,"tls":"mitm"}'
   ```
   Pick a port that is not Burp's own Proxy listener (8080 by default). Optional auth: add
   `"username"` / `"password"`. Never paste the real token into shared notes.
2. **Burp → Settings → Network → Connections → SOCKS proxy**: enable it, host `127.0.0.1`, the port
   above, username/password if set, and tick **Do DNS lookups over SOCKS proxy**. This applies to all
   of Burp's outbound traffic.
3. **Make Burp trust Expedition's certificates** (Burp now sees certs minted by the Expedition CA).
   Either allow invalid server certificates in Settings → Network → TLS (test setups only), or import
   `~/.expedition/expedition-ca.crt` into the Java truststore Burp uses (the `jvm` setup target builds
   one) and restart Burp. "Server TLS certificates" is for client certificates and does not add trusted
   CAs. Menu names differ between Burp versions.
4. **Verify**: add a mock rule, then `curl -sk -i -x http://127.0.0.1:8080 https://example.com/`
   (your Burp Proxy port) should return the mocked response. Test the listener alone with
   `curl -sk --socks5-hostname 127.0.0.1:<port> https://example.com/`.

Caveats: Burp sees Expedition's certificate (scope and Scanner still work, certificate findings reflect
Expedition); rules match HTTP/1.x only. While a rule is enabled Expedition offers only `http/1.1`, so
Burp negotiates HTTP/1.1 on that leg; with no rule enabled HTTP/2 passes through as bytes and no rule
can apply. A mock may still return 502 if the flow needs the upstream and the host is down. This chain
has been exercised only by Expedition's own tests, not yet inside a running Burp Suite; menu names and
the exact trust steps may differ between Burp versions.

## Control API

An opt-in loopback JSON REST API (default **`127.0.0.1:18112`**) so an external client — such as the
[Praetor](https://github.com/TyrusRC/praetor) MCP server — can drive the proxy programmatically.

- **Opt-in:** off by default; a Burp extension should not open a listening socket on load unless
  asked. Set **`EXPEDITION_API_ENABLE=1`** to start it.
- **Token (mandatory):** every request must send `Authorization: Bearer <token>` (compared in
  constant time); there is no unauthenticated mode. The token is `EXPEDITION_API_TOKEN` if set,
  otherwise a random 256-bit token generated on first start and stored owner-only (`0600`) in
  **`~/.expedition/api-token`** (reused on later starts; delete the file to rotate). The Burp
  extension output says which applies.
- **Security:** loopback-only by default; a non-loopback `EXPEDITION_API_HOST` is **refused** unless
  `EXPEDITION_API_TOKEN` is set explicitly. Every request's `Host` is checked against literal loopback
  / the bind host (DNS-rebinding safe, never resolves a hostname) and any browser request (an
  `Origin` or `Sec-Fetch-*` header, even from localhost) is rejected. File paths the API accepts
  (`/session/save|load`, `client_cert`, setup `ca`/`truststore`) are canonicalised and must stay
  inside `~/.expedition` (or `EXPEDITION_CA_DIR`); relative paths resolve there, `..` and symlinks
  leading outside are refused. Setup `binary` must be a known browser name or an executable listed in
  `EXPEDITION_BROWSER_BINARIES` (path-separator list); setup values such as `device_host`, `serial`,
  `package`, `gateway`, `storepass`, `url` are allow-listed (no shell/option syntax). `timeout_ms` is
  capped (30 s repeat, 5 s per fuzz case) and slow calls run on a separate bounded pool (503 when
  full). Request bodies are capped at 4 MiB. The API can start proxies and send arbitrary bytes, so
  never expose it to an untrusted network.
- **Env:** `EXPEDITION_API_ENABLE=1` to turn it on; `EXPEDITION_API_PORT` (default `18112`);
  `EXPEDITION_API_DISABLE=1` as a kill switch overriding enable; `EXPEDITION_API_TOKEN` to choose the
  token; `EXPEDITION_API_HOST` to bind a non-loopback interface **only** when the client is off-host
  (NAT-mode WSL reaching Burp on the Windows IP) — set the reachable IP, not `0.0.0.0`, and an
  explicit token. A warning is logged when bound beyond loopback.

| Method + path | Purpose |
|---|---|
| `GET /status` | version, running listeners, connection/message counts |
| `GET /listeners` · `POST /listeners` · `DELETE /listeners/{name}` | list / add+start / stop a listener¹ |
| `GET /connections` | captured connection summaries |
| `GET /connections/{id}/messages` · `GET /messages?limit=N` | captured messages (hex + ASCII preview) |
| `POST /repeat` | Repeater — send a raw TCP/UDP payload, read the response |
| `POST /fuzz` | Mutation fuzzer — send N mutated payloads, collect responses + anomalies |
| `GET /matchreplace` · `POST /matchreplace` · `DELETE /matchreplace/{id}` | list / add / remove rules |
| `GET /intercept` · `POST /intercept/enable` | held-message queue + toggle live intercept |
| `POST /intercept/{id}/forward` · `POST /intercept/{id}/drop` | forward (edited or unchanged) / drop a held message |
| `POST /connections/{id}/tag` · `GET /connections/{id}/tags` | add a flow tag (`color`/`comment`) / read a connection's tags |
| `GET /messages/search?q=…&limit=N` | messages whose ASCII preview contains `q` |
| `POST /session/save` · `POST /session/load` · `GET /session/export` | save snapshot to a path / load tags from a path / return the snapshot JSON |
| `GET /script` · `POST /script` · `DELETE /script` | script status / install (`source`; 400 on compile error) / clear the transform script |
| `GET /dns` · `POST /dns/start` · `POST /dns/stop` | DNS redirector status / start (`rules:[{host,ip}]`, `default_ip`, `port`) / stop |

```sh
T="Authorization: Bearer $(cat ~/.expedition/api-token)"   # or $EXPEDITION_API_TOKEN
curl -s -H "$T" 127.0.0.1:18112/status
curl -s -H "$T" -XPOST 127.0.0.1:18112/listeners \
  -d '{"name":"redis","protocol":"tcp","bind_port":16379,"upstream_host":"10.0.0.5","upstream_port":6379}'
curl -s -H "$T" -XPOST 127.0.0.1:18112/repeat \
  -d '{"protocol":"tcp","host":"10.0.0.5","port":6379,"text":"PING\r\n"}'
```

¹ `POST /listeners` also accepts `"protocol":"socks5"`, `"tls":"mitm"|"starttls"`,
`"upstream_proxy":"host:port"`, and `"client_cert":"/path.p12"` + `"client_cert_password"`.
MITM leaves are minted per connection from the ClientHello SNI (fallback: `upstream_host`).
`"tls_passthrough":["host","*.suffix"]` relays matching-SNI TLS raw (not decrypted; history gets a
`TLS PASSTHROUGH` note). SOCKS5 listeners also take `tls`, `upstream_proxy`, `tls_passthrough`
and optional RFC 1929 auth via `"username"` + `"password"` (STARTTLS is not supported on SOCKS5).
TCP framing (default `"framing":"passthrough"` — one message per socket read) can be set with
`"framing":"delimiter"` (+ `"delimiter":"\r\n"` or `"delimiter_hex"`) or `"framing":"length"`
(+ `"length_offset"`, `"length_size"` 1/2/3/4/8, `"length_endian":"big"|"little"`,
`"length_adjust"`); `"max_frame_bytes"` (default 1 MiB) caps buffering — beyond it bytes are
flushed raw with a warning. Frames keep their header/delimiter; match-and-replace does not
rewrite length fields. Held intercept messages are released FIFO per connection and direction.

## Architecture

Kotlin (JVM 17), Gradle Kotlin DSL, Netty (proxy engine), Bouncy Castle (CA / cert minting),
Montoya API, JUnit 5. Exact versions are in [`build.gradle.kts`](build.gradle.kts). The dissector
layer is a small SPI (`supports` / `render` / `parseEdit`) with a single ordered registry, so adding
a protocol is one class plus a line in `defaultDissectors()`.

## Scope & limitations

Explicit-proxy only — clients are pointed at a listener directly or routed via SOCKS5; no
transparent/OS-level redirection (the DNS redirector is the recommended way to steer clients). UDP
listeners are plaintext (no TLS/STARTTLS). The dissectors decode the common cases per protocol;
anything beyond their documented editable fields falls back to hex. Pure-JVM (Nio transport only),
so it runs the same on Linux, macOS and Windows.

## Known limitations vs HTTP Toolkit Pro

- The Burp → SOCKS chain has **not been tested in a real Burp instance** yet; it is built from the
  documented Burp settings and Expedition's own tests.
- Rules apply to **HTTP/1.x only**; **HTTP/2 is passthrough** (bytes, no rule matching).
- Android system-CA install, Frida native hooks, Flutter, Docker and JVM-attach flows are
  **command generators only** (Setup tab): they produce commands/scripts, are not end-to-end verified
  and may need manual steps (root, device state, app-specific pinning).

## Troubleshooting

### Build fails: `PKIX path building failed` / `SSL handshake exception` when downloading dependencies

Your network has a **TLS-intercepting proxy** (common on corporate/VPN networks): it re-signs HTTPS
with a company root CA that the JDK's truststore doesn't trust, so Gradle can't download the
Kotlin/Shadow plugins. The error looks like:

```
Could not download kotlin-compiler-embeddable-...jar
Got SSL handshake exception ... PKIX path building failed:
  unable to find valid certification path to requested target
```

Fix: import your corporate root CA into the **JDK** truststore (it's not about this project — it
affects any Gradle/Java build on that network). First confirm which JDK Gradle uses:

```sh
./gradlew --version    # note the "JVM: ..." line
```

**Get the corporate root CA** — export it from your OS trust store, or:
```sh
openssl s_client -showcerts -connect plugins.gradle.org:443 </dev/null 2>/dev/null \
  | awk '/BEGIN CERT/,/END CERT/' > corp-root.pem   # last block = the proxy's root CA
```

**Import it into that JDK** (`-cacerts` targets the running keytool's JDK — export `JAVA_HOME` to the
one from `--version` first; needs admin/sudo):

```sh
# macOS
export JAVA_HOME=$(/usr/libexec/java_home -v 21)
sudo keytool -importcert -trustcacerts -cacerts -storepass changeit -alias corp-root -noprompt -file corp-root.pem

# Linux
sudo keytool -importcert -trustcacerts -cacerts -storepass changeit -alias corp-root -noprompt -file corp-root.pem

# Windows (admin PowerShell) — adjust to your JDK path
& "$env:JAVA_HOME\bin\keytool.exe" -importcert -trustcacerts -cacerts -storepass changeit -alias corp-root -noprompt -file corp-root.pem
```

Then rebuild. **macOS shortcut:** since the CA is already in your keychain, you can instead add
`systemProp.javax.net.ssl.trustStoreType=KeychainStore` to `~/.gradle/gradle.properties`. If your
network also requires an explicit proxy, set `systemProp.https.proxyHost` / `systemProp.https.proxyPort`
there too. Never disable TLS verification to work around this.

If the machine is too locked down to fetch dependencies at all, build on an unrestricted machine and
copy the self-contained jar over.

### `Cannot find a Java installation ... matching ... languageVersion=17`

An older build pinned a JDK 17 *toolchain*. The current build compiles with whatever JDK runs Gradle
(≥17) and targets JVM 17, so just use a JDK 17+ — no separate JDK 17 install needed.

## Contributing

Issues and pull requests are welcome. Please:

- Build and run the tests (`./gradlew test`) before opening a PR; new behaviour comes with a test.
- Follow the existing dissector SPI when adding a protocol (one class + a line in
  `defaultDissectors()`), and keep changes focused.
- Don't commit build output, local CA material (`~/.expedition/`) or anything secret.

## License

[Apache-2.0](LICENSE).
