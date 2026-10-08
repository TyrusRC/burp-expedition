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

Requires a **JDK 17 or newer** on `PATH` (JDK 21 is fine — the build targets JVM 17
bytecode regardless, so it loads in Burp's bundled JRE). No separate Gradle install is
needed; the wrapper fetches everything.

```sh
# macOS / Linux
./gradlew shadowJar

# Windows (PowerShell / cmd)
gradlew.bat shadowJar
```

Produces a self-contained extension at `build/libs/burp-expedition-0.1.0.jar`. Bundled
dependencies (Netty, Bouncy Castle) are relocated under `expedition.shaded.*`; the Montoya
API is `compileOnly` and supplied by Burp at runtime. Pure-JVM (Nio transport), so the same
jar runs on macOS, Linux, and Windows.

## Install

1. Build the jar (above), or copy a prebuilt `burp-expedition-0.1.0.jar`.
2. In Burp: **Extensions** → **Add** → Extension type: **Java** → select the jar.
3. The extension loads as **"Burp Expedition v0.1.0"** and adds an **Expedition** suite tab
   with four sub-tabs: Listeners, Intercept, History, Match & Replace. TLS works out of the
   box via an auto-generated CA (see below).

To update: rebuild, then in **Extensions** untick and re-tick the extension (or remove and
re-add) to reload the new jar.

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

## Troubleshooting

### Build fails: `PKIX path building failed` / `SSL handshake exception` when downloading dependencies

Your network has a **TLS-intercepting proxy** (common on corporate/VPN networks): it re-signs
HTTPS with a company root CA that the JDK's truststore doesn't trust, so Gradle can't download
the Kotlin/Shadow plugins. The error looks like:

```
Could not download kotlin-compiler-embeddable-...jar
Got SSL handshake exception ... PKIX path building failed:
  unable to find valid certification path to requested target
```

Fix: import your corporate root CA into the **JDK** truststore (it's not about this project —
it affects any Gradle/Java build on that network). First confirm which JDK Gradle uses:

```sh
./gradlew --version    # note the "JVM: ..." line
```

**Get the corporate root CA** — export it from your OS trust store, or:
```sh
openssl s_client -showcerts -connect plugins.gradle.org:443 </dev/null 2>/dev/null \
  | awk '/BEGIN CERT/,/END CERT/' > corp-root.pem   # last block = the proxy's root CA
```

**Import it into that JDK** (`-cacerts` targets the running keytool's JDK — export
`JAVA_HOME` to the one from `--version` first; needs admin/sudo):

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
`systemProp.javax.net.ssl.trustStoreType=KeychainStore` to `~/.gradle/gradle.properties`.
If your network also requires an explicit proxy, set `systemProp.https.proxyHost` /
`systemProp.https.proxyPort` there too. Never disable TLS verification to work around this.

If the machine is too locked down to fetch dependencies at all, build on an unrestricted
machine and copy the self-contained `build/libs/burp-expedition-0.1.0.jar` over.

### `Cannot find a Java installation ... matching ... languageVersion=17`

An older build pinned a JDK 17 *toolchain*. The current build compiles with whatever JDK runs
Gradle (≥17) and targets JVM 17, so just use a JDK 17+ — no separate JDK 17 install needed.

## License

[Apache-2.0](LICENSE).
