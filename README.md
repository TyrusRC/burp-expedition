# Burp Expedition

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Kotlin](https://img.shields.io/badge/Kotlin-2.0-7F52FF.svg?logo=kotlin&logoColor=white)](build.gradle.kts)
[![JDK 17+](https://img.shields.io/badge/JDK-17%2B-ED8B00.svg?logo=openjdk&logoColor=white)](#building)
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
- [Control API](#control-api)
- [Architecture](#architecture)
- [Scope & limitations](#scope--limitations)
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
  (Burp ships Groovy) and is a safe no-op when none is present.
- **Fail-safe:** a compile error is rejected when you apply the script; a runtime error forwards the
  original bytes unchanged and is surfaced, never dropping or corrupting traffic.
- **⚠️ Full JVM privileges, no sandbox** — by design, the same trust level as any Burp extension.
  Only an operator who already controls the Burp process can set a script (local UI / loopback API).
  Never wire script-setting to untrusted input.

## Control API

An opt-in loopback JSON REST API (default **`127.0.0.1:18112`**) so an external client — such as the
[Praetor](https://github.com/TyrusRC/praetor) MCP server — can drive the proxy programmatically.

- **Opt-in:** off by default; a Burp extension should not open a listening socket on load unless
  asked. Set **`EXPEDITION_API_ENABLE=1`** to start it.
- **Security:** loopback-only by default; every request's `Host` is checked against literal loopback
  (DNS-rebinding safe, never resolves a hostname) and a cross-site `Origin` is rejected (CSRF).
  Request bodies are capped at 4 MiB. The API can start proxies and send arbitrary bytes, so never
  expose it to an untrusted network.
- **Env:** `EXPEDITION_API_ENABLE=1` to turn it on; `EXPEDITION_API_PORT` (default `18112`);
  `EXPEDITION_API_DISABLE=1` as a kill switch overriding enable; `EXPEDITION_API_TOKEN` to require an
  `Authorization: Bearer <token>` on every request (do this whenever bound beyond loopback);
  `EXPEDITION_API_HOST` to bind a non-loopback interface **only** when the client is off-host
  (NAT-mode WSL reaching Burp on the Windows IP) — set the reachable IP, not `0.0.0.0`. A warning is
  logged when bound beyond loopback.

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
curl -s 127.0.0.1:18112/status
curl -s -XPOST 127.0.0.1:18112/listeners \
  -d '{"name":"redis","protocol":"tcp","bind_port":16379,"upstream_host":"10.0.0.5","upstream_port":6379}'
curl -s -XPOST 127.0.0.1:18112/repeat \
  -d '{"protocol":"tcp","host":"10.0.0.5","port":6379,"text":"PING\r\n"}'
```

¹ `POST /listeners` also accepts `"protocol":"socks5"`, `"tls":"mitm"|"starttls"`,
`"upstream_proxy":"host:port"`, and `"client_cert":"/path.p12"` + `"client_cert_password"`.

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
