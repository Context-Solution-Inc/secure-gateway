import Foundation

/// Connection states surfaced to the host app (PRD §8). `superseded`/`revoked` are terminal.
public enum ConnectionState {
    case connected, reconnecting, peerOffline, revoked, superseded
}

/// Push-to-wake seam (PRD §8.2): APNs wakes a backgrounded app when the desktop's message
/// returns peer_offline. Real wiring lives in the host app.
public protocol PushWaker {
    func register(deviceToken: String)
    func awaitWake() async
}

public final class NoopPushWaker: PushWaker {
    public init() {}
    public func register(deviceToken: String) {}
    public func awaitWake() async { try? await Task.sleep(nanoseconds: .max) }
}

/// The relay client engine on `URLSessionWebSocketTask` (PRD §8.2), mirroring the JVM
/// `ConnectionManager`: per-session E2EE handshake, reconnect with full-jitter backoff
/// (base 1s, cap 60s), token refresh over the live socket, ack correlation, and the
/// connected/reconnecting/peer_offline/revoked/superseded state machine. The connection JWT
/// is set as the `Authorization: Bearer` header on the upgrade request (FR-1.2).
///
/// Serialized on a private actor-like serial queue (`queue`) so state is race-free.
public final class ConnectionManager: NSObject {
    private let wsURL: URL
    private let role: Role
    private let myPriv: Data
    private let peerPub: Data
    private let auth: AuthClient
    private var token: String
    private var refresh: String

    private let queue = DispatchQueue(label: "com.securegateway.conn")
    private var task: URLSessionWebSocketTask?
    private var urlSession: URLSession!
    private var handshake: HandshakeCoordinator?
    private var pendingAcks: [String: CheckedContinuation<Void, Error>] = [:]
    private var bufferedData: [Envelope] = []
    private var attempt = 0
    private var terminal = false
    private(set) var state: ConnectionState = .reconnecting

    public var onMessage: (Data) -> Void = { _ in }
    public var onStateChange: (ConnectionState) -> Void = { _ in }

    public init(wsURL: String, role: Role, myPriv: Data, peerPub: Data,
                auth: AuthClient, token: String, refresh: String) {
        self.wsURL = URL(string: wsURL)!
        self.role = role
        self.myPriv = myPriv
        self.peerPub = peerPub
        self.auth = auth
        self.token = token
        self.refresh = refresh
        super.init()
        self.urlSession = URLSession(configuration: .default)
    }

    public func start() {
        queue.async { self.connect() }
    }

    public func send(_ plaintext: Data) async throws {
        let id = UUID().uuidString
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
            queue.async {
                guard !self.terminal, let hs = self.handshake, hs.isComplete else {
                    cont.resume(throwing: CryptoError.sealFailed) // not connected yet
                    return
                }
                self.pendingAcks[id] = cont
                do {
                    let ts = Int64(Date().timeIntervalSince1970 * 1000)
                    let frame = try hs.sealFrame(id: id, ts: ts, plaintext: plaintext)
                    self.write(Protocol.msg(id: id, ts: ts, ciphertext: frame))
                } catch {
                    self.pendingAcks[id] = nil
                    cont.resume(throwing: error)
                }
            }
        }
    }

    public func close() {
        queue.async {
            self.terminal = true
            self.task?.cancel(with: .normalClosure, reason: nil)
        }
    }

    // MARK: - connection lifecycle (all on `queue`)

    private func connect() {
        guard !terminal else { return }
        var req = URLRequest(url: wsURL)
        req.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        let t = urlSession.webSocketTask(with: req)
        self.task = t
        t.resume()
        handshake = HandshakeCoordinator(myPriv: myPriv, peerPub: peerPub, myRole: role)
        let ts = Int64(Date().timeIntervalSince1970 * 1000)
        write(Protocol.msg(id: UUID().uuidString, ts: ts, ciphertext: handshake!.handshakeFrame()))
        attempt = 0
        setState(.connected)
        receiveLoop()
    }

    private func receiveLoop() {
        task?.receive { [weak self] result in
            guard let self else { return }
            self.queue.async {
                switch result {
                case .success(let message):
                    let data: Data
                    switch message {
                    case .data(let d): data = d
                    case .string(let s): data = Data(s.utf8)
                    @unknown default: data = Data()
                    }
                    self.handleMessage(data)
                    self.receiveLoop()
                case .failure:
                    self.handleClose(code: CloseCode.goingAway)
                }
            }
        }
    }

    private func handleMessage(_ data: Data) {
        guard let env = try? Protocol.decode(data) else { return }
        switch env.type {
        case MessageType.msg: handleMsg(env)
        case MessageType.ack: pendingAcks.removeValue(forKey: env.id)?.resume()
        case MessageType.sys: handleSys(env)
        case MessageType.error:
            if Protocol.errorCode(env) == ErrorCode.peerOffline {
                setState(.peerOffline)
                failPending(CryptoError.openFailed)
            }
        default: break
        }
    }

    private func handleMsg(_ env: Envelope) {
        guard let payload = Protocol.ciphertext(env), let first = payload.first, let hs = handshake else { return }
        if first == HandshakeCoordinator.tagHandshake {
            _ = try? hs.onFrame(payload, id: env.id, ts: env.ts)
            if hs.isComplete { drainBuffered() }
            return
        }
        if !hs.isComplete { bufferedData.append(env); return }
        deliver(env, payload)
    }

    private func deliver(_ env: Envelope, _ payload: Data) {
        guard let hs = handshake, let plaintext = try? hs.onFrame(payload, id: env.id, ts: env.ts) else { return }
        write(Protocol.ack(id: env.id, ts: Int64(Date().timeIntervalSince1970 * 1000)))
        onMessage(plaintext)
    }

    private func drainBuffered() {
        let buffered = bufferedData; bufferedData = []
        for env in buffered { if let p = Protocol.ciphertext(env) { deliver(env, p) } }
    }

    private func handleSys(_ env: Envelope) {
        switch Protocol.sysKind(env) {
        case SysKind.peerOnline:
            setState(.connected)
            if let hs = handshake {
                write(Protocol.msg(id: UUID().uuidString, ts: Int64(Date().timeIntervalSince1970 * 1000), ciphertext: hs.handshakeFrame()))
            }
        case SysKind.peerOffline: setState(.peerOffline)
        case SysKind.shutdown: scheduleReconnect()
        default: break
        }
    }

    private func handleClose(code: Int) {
        failPending(CryptoError.openFailed)
        handshake = nil
        switch code {
        case CloseCode.superseded: terminate(.superseded)
        case CloseCode.revoked: terminate(.revoked)
        case CloseCode.tokenExpired: Task { await self.refreshNow() }; scheduleReconnect()
        default: scheduleReconnect()
        }
    }

    private func scheduleReconnect() {
        guard !terminal else { return }
        setState(.reconnecting)
        let cap = 60_000.0, base = 1_000.0
        let exp = min(cap, base * pow(2.0, Double(attempt)))
        attempt += 1
        let delay = Double.random(in: 0...exp) / 1000.0
        queue.asyncAfter(deadline: .now() + delay) { self.connect() }
    }

    private func refreshNow() async {
        if let r = try? await auth.refreshToken(refresh) {
            queue.async {
                self.token = r.token
                self.refresh = r.refreshToken
                self.write(Protocol.authRefresh(id: UUID().uuidString, ts: Int64(Date().timeIntervalSince1970 * 1000), token: r.token))
            }
        }
    }

    private func write(_ env: Envelope) {
        guard let data = try? Protocol.encode(env), let s = String(data: data, encoding: .utf8) else { return }
        task?.send(.string(s)) { _ in }
    }

    private func failPending(_ error: Error) {
        for (_, cont) in pendingAcks { cont.resume(throwing: error) }
        pendingAcks = [:]
    }

    private func terminate(_ s: ConnectionState) {
        terminal = true
        failPending(CryptoError.openFailed)
        setState(s)
    }

    private func setState(_ s: ConnectionState) {
        state = s
        onStateChange(s)
    }
}
