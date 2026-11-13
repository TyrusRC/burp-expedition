package expedition.server

import java.net.URI
import java.net.http.HttpRequest

/** Bearer token the control-API tests start their servers with (auth is mandatory). */
const val TEST_TOKEN = "test-token-0123456789abcdef0123456789abcdef"

/** A request builder that already carries the test bearer token. */
fun authed(uri: URI): HttpRequest.Builder =
    HttpRequest.newBuilder(uri).header("Authorization", "Bearer $TEST_TOKEN")
