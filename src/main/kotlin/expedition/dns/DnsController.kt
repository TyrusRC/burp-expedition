package expedition.dns

/**
 * Owns the single running [DnsServer] so the UI, the control API and the unload handler share
 * one lifecycle. start() replaces any running server; stop() is idempotent. Synchronised because
 * start/stop can arrive from the Swing EDT and the control API threads at once.
 */
class DnsController(private val onError: (String) -> Unit = {}) {

    private var server: DnsServer? = null
    private var host: String = ""
    private var port: Int = 0
    private var rules: List<DnsRedirector.Rule> = emptyList()
    private var defaultIp: String? = null

    @Synchronized
    fun start(host: String, port: Int, rules: List<DnsRedirector.Rule>, defaultIp: String?): Int {
        stop()
        val s = DnsServer(host, port, DnsRedirector(rules, defaultIp), onError)
        s.start()
        this.server = s
        this.host = host
        this.port = s.boundPort()
        this.rules = rules
        this.defaultIp = defaultIp
        return this.port
    }

    @Synchronized
    fun stop() {
        server?.stop()
        server = null
    }

    @Synchronized
    fun isRunning(): Boolean = server != null

    @Synchronized
    fun status(): Map<String, Any?> = mapOf(
        "running" to (server != null),
        "host" to host,
        "port" to port,
        "default_ip" to defaultIp,
        "rules" to rules.map { mapOf("host" to it.hostPattern, "ip" to it.ip) },
    )
}
