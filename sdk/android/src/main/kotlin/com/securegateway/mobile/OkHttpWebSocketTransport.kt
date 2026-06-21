package com.securegateway.mobile

import com.securegateway.core.transport.EndpointValidator
import com.securegateway.core.transport.Transport
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import okio.ByteString
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference

/**
 * Mobile [Transport] on OkHttp's WebSocket (PRD §8.1). The connection JWT is set as the
 * `Authorization: Bearer` header on the upgrade request (FR-1.2). OkHttp's `pingInterval`
 * drives the 25s heartbeat and fails the socket on a missed pong, so this transport
 * reports [selfManagesLiveness] = true and the manager skips its own watchdog.
 */
class OkHttpWebSocketTransport(
    private val client: OkHttpClient = OkHttpClient.Builder()
        .pingInterval(25, TimeUnit.SECONDS)
        .build(),
    // Diagnostics sink (defaults no-op). The wss dial happens here, and the relay state
    // machine swallows connect failures into a silent reconnect — so this is where the
    // real cause (refused/TLS/401/relay close code) is visible. Host wires it to its log.
    private val logger: (String) -> Unit = {},
) : Transport {

    private val socket = AtomicReference<WebSocket?>(null)

    override fun connect(wsUrl: String, bearerToken: String, listener: Transport.Listener) {
        // Enforce wss:// (except loopback/RFC1918) before dialing, so the Bearer token on the
        // upgrade is never sent over cleartext ws:// from an untrusted QR endpoint (SG-14).
        EndpointValidator.requireSecureRelay(wsUrl)
        // OkHttp's HttpUrl uses http/https; map the ws/wss scheme accordingly.
        val httpUrl = wsUrl.replaceFirst(Regex("^ws"), "http")
        logger("wss: dialing $httpUrl (token=${bearerToken.length}B)")
        val request = Request.Builder()
            .url(httpUrl)
            .header("Authorization", "Bearer $bearerToken")
            .build()

        val opened = CountDownLatch(1)
        val failure = AtomicReference<Throwable?>(null)

        val ws = client.newWebSocket(request, object : WebSocketListener() {
            override fun onOpen(webSocket: WebSocket, response: Response) {
                logger("wss: onOpen http=${response.code}")
                response.close()
                opened.countDown()
                listener.onOpen()
            }

            override fun onMessage(webSocket: WebSocket, text: String) {
                listener.onActivity()
                listener.onMessage(text.toByteArray(Charsets.UTF_8))
            }

            override fun onMessage(webSocket: WebSocket, bytes: ByteString) {
                listener.onActivity()
                listener.onMessage(bytes.toByteArray())
            }

            override fun onClosing(webSocket: WebSocket, code: Int, reason: String) {
                logger("wss: onClosing code=$code reason='$reason'")
                listener.onClosed(code, reason)
            }

            override fun onClosed(webSocket: WebSocket, code: Int, reason: String) {
                logger("wss: onClosed code=$code reason='$reason'")
                listener.onClosed(code, reason)
            }

            override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
                logger("wss: onFailure ${t.javaClass.simpleName}: ${t.message}" +
                    (response?.let { " (http=${it.code})" } ?: "") +
                    if (opened.count > 0) " [pre-open]" else " [post-open]")
                response?.close()
                if (opened.count > 0) {
                    failure.set(t)
                    opened.countDown()
                } else {
                    listener.onError(t)
                }
            }
        })
        socket.set(ws)

        if (!opened.await(20, TimeUnit.SECONDS)) {
            logger("wss: open timed out after 20s (no onOpen/onFailure) — relay unreachable?")
            ws.cancel()
            throw java.io.IOException("websocket open timed out")
        }
        failure.get()?.let { ws.cancel(); throw it }
        logger("wss: connected")
    }

    override fun send(frame: ByteArray) {
        val ws = socket.get()
        if (ws == null) {
            logger("wss: send dropped — socket is null (not connected)")
            return
        }
        val accepted = ws.send(String(frame, Charsets.UTF_8))
        if (!accepted) logger("wss: send rejected (buffer full / closing), ${frame.size}B")
    }

    override fun selfManagesLiveness(): Boolean = true

    override fun close(code: Int, reason: String) {
        val c = if (code == 1000 || code in 3000..4999) code else 1000
        socket.get()?.close(c, reason.take(120))
    }
}
