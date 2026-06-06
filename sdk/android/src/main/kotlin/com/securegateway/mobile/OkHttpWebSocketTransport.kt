package com.securegateway.mobile

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
) : Transport {

    private val socket = AtomicReference<WebSocket?>(null)

    override fun connect(wsUrl: String, bearerToken: String, listener: Transport.Listener) {
        // OkHttp's HttpUrl uses http/https; map the ws/wss scheme accordingly.
        val httpUrl = wsUrl.replaceFirst(Regex("^ws"), "http")
        val request = Request.Builder()
            .url(httpUrl)
            .header("Authorization", "Bearer $bearerToken")
            .build()

        val opened = CountDownLatch(1)
        val failure = AtomicReference<Throwable?>(null)

        val ws = client.newWebSocket(request, object : WebSocketListener() {
            override fun onOpen(webSocket: WebSocket, response: Response) {
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
                listener.onClosed(code, reason)
            }

            override fun onClosed(webSocket: WebSocket, code: Int, reason: String) {
                listener.onClosed(code, reason)
            }

            override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
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
            ws.cancel()
            throw java.io.IOException("websocket open timed out")
        }
        failure.get()?.let { ws.cancel(); throw it }
    }

    override fun send(frame: ByteArray) {
        socket.get()?.send(String(frame, Charsets.UTF_8))
    }

    override fun selfManagesLiveness(): Boolean = true

    override fun close(code: Int, reason: String) {
        val c = if (code == 1000 || code in 3000..4999) code else 1000
        socket.get()?.close(c, reason.take(120))
    }
}
