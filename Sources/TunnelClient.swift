import Darwin
import Foundation

enum Operation: String, Sendable {
    case status, up, down

    var title: String {
        switch self {
        case .status: "刷新状态"
        case .up: "连接"
        case .down: "断开"
        }
    }

    var progress: String {
        switch self {
        case .status: "正在刷新状态…"
        case .up: "正在建立隧道…"
        case .down: "正在断开隧道…"
        }
    }
}

struct Metrics: Equatable, Sendable {
    let handshake: Date?
    let received: UInt64
    let sent: UInt64
    let peers: Int

    func hasRecentHandshake(at now: Date) -> Bool {
        guard let handshake else { return false }
        let age = now.timeIntervalSince(handshake)
        return age >= 0 && age <= 180
    }
}

enum TunnelState: Equatable, Sendable {
    case unknown, inactive, conflict
    case active(Metrics)
}

struct TunnelReply: Sendable {
    let state: TunnelState
    let message: String?
    let cancelled: Bool

    static func decode(_ output: String, operation: Operation) -> TunnelReply {
        var lines = output.split(separator: "\n").makeIterator()
        let code = lines.next()
        let state: TunnelState
        switch lines.next() {
        case "inactive": state = .inactive
        case "conflict": state = .conflict
        case "active": state = parseMetrics(lines).map(TunnelState.active) ?? .unknown
        default: state = .unknown
        }

        let message: String?
        switch code {
        case "OK":
            message = state == .unknown
                ? "无法读取隧道状态。请稍后刷新；若仍失败，请检查 WireGuard 接口。"
                : nil
        case "CANCELLED": message = "已取消管理员授权。"
        case "AUTH_FAILED": message = "管理员授权未完成。请使用 macOS 管理员账户重试。"
        case "SESSION_FAILED":
            message = "无法建立可复用的授权会话。下次操作将使用单次授权。"
        case "BUSY": message = "另一个应用窗口正在操作 WireGuard。请稍后刷新。"
        case "MISSING_TOOLS":
            message = "缺少 /opt/homebrew 下的 ARM 版 bash、wg、wg-quick 或 wireguard-go。"
        case "UNSUPPORTED_TOOLS":
            message = "当前 wg-quick 脚本格式不兼容。请核对 ARM Homebrew 的 wireguard-tools 版本。"
        case "SNAPSHOT_FAILED":
            message = "无法验证本次授权的配置副本。请重新选择文件并重试。"
        case "UNSAFE_CONFIG":
            message = "配置含命令钩子或启用了 SaveConfig，操作已停止。"
        case "STATE_CONFLICT":
            message = state == .conflict
                ? "同名隧道的本机或对端公钥与配置不同。请选择建立该隧道时使用的配置。"
                : "无法核对当前接口。请刷新状态后重试。"
        case "ALREADY_UP": message = "此配置对应的隧道已建立，请查看握手状态。"
        case "ALREADY_DOWN": message = "此配置对应的隧道已经断开。"
        case "COMMAND_FAILED":
            message = operation == .up
                ? "未能建立隧道。请检查配置中的地址、Endpoint、路由冲突和 ARM Homebrew 依赖。"
                : "断开未确认完成。请刷新状态后重试。"
        default: message = "无法完成本机 WireGuard 操作。请重试。"
        }
        return TunnelReply(state: state, message: message, cancelled: code == "CANCELLED")
    }

    private static func parseMetrics(_ lines: IndexingIterator<[Substring]>) -> Metrics? {
        var handshakes = 0
        var transfers = 0
        var latest: UInt64 = 0
        var received: UInt64 = 0
        var sent: UInt64 = 0
        for line in IteratorSequence(lines) {
            let columns = line.split(separator: " ")
            if columns.count == 2, columns[0] == "h",
               let epoch = UInt64(columns[1]), epoch < 253_402_300_800 {
                handshakes += 1
                latest = max(latest, epoch)
            } else if columns.count == 3, columns[0] == "t",
                      let rx = UInt64(columns[1]), let tx = UInt64(columns[2]) {
                transfers += 1
                received = addBytes(received, rx)
                sent = addBytes(sent, tx)
            } else {
                return nil
            }
        }
        guard handshakes == transfers else { return nil }
        let handshake = latest == 0 ? nil : Date(timeIntervalSince1970: TimeInterval(latest))
        return Metrics(handshake: handshake, received: received, sent: sent, peers: handshakes)
    }

    private static func addBytes(_ left: UInt64, _ right: UInt64) -> UInt64 {
        let (sum, overflow) = left.addingReportingOverflow(right)
        return overflow ? UInt64.max : sum
    }
}

enum TunnelClient {
    enum Observation: Sendable {
        case snapshot(TunnelState)
        case paused
        case skipped
    }

    private static let lock = NSLock()
    private static var session: AuthorizationSession?
    private static var sessionUnavailable = false

    static func observe(_ reference: TunnelReference) -> Observation {
        guard lock.try() else { return .skipped }
        defer { lock.unlock() }
        guard let session, session.isUsable else {
            session = nil
            return .paused
        }
        do {
            let reply = try session.observe(reference)
            let snapshot = TunnelReply.decode(reply, operation: .status).state
            return snapshot == .unknown ? .skipped : .snapshot(snapshot)
        } catch {
            self.session = nil
            return .paused
        }
    }

    static func perform(_ operation: Operation, config: TunnelConfig) throws -> TunnelReply {
        lock.lock()
        defer { lock.unlock() }
        let staged: URL?
        if operation == .status {
            staged = nil
        } else {
            if let error = config.mutationError { throw error }
            staged = try config.stage()
        }
        defer {
            if let staged { try? FileManager.default.removeItem(at: staged.deletingLastPathComponent()) }
        }

        if session?.isUsable == false { session = nil }
        if session == nil && !sessionUnavailable {
            if let tools = try? SessionToolkit.prepare() {
                do {
                    switch try AuthorizationSession.start(tools: tools) {
                    case .connected(let connection):
                        session = connection
                    case .rejected(let response):
                        if response.hasPrefix("SESSION_FAILED") { sessionUnavailable = true }
                        return TunnelReply.decode(response, operation: operation)
                    }
                } catch {
                    sessionUnavailable = true
                    return TunnelReply.decode("SESSION_FAILED", operation: operation)
                }
            } else {
                sessionUnavailable = true
            }
        }
        if let session {
            do {
                let response = try session.run(operation, config: config, staged: staged)
                return TunnelReply.decode(response, operation: operation)
            } catch {
                self.session = nil
                throw error
            }
        }

        let child = authorizationProcess(arguments: [
            PrivilegedScripts.bootstrap, "--", PrivilegedScripts.worker,
            operation.rawValue, config.name, config.identity, String(getuid()),
            staged?.path ?? "", staged == nil ? "" : TunnelConfig.digest(config.data)
        ])
        let pipe = Pipe()
        child.standardOutput = pipe
        do {
            try child.run()
        } catch {
            throw UserError("无法启动 macOS 管理员授权。请重新打开应用。")
        }
        let output = pipe.fileHandleForReading.readDataToEndOfFile()
        child.waitUntilExit()
        guard child.terminationStatus == 0, output.count <= 2_000_000,
              let response = String(data: output, encoding: .utf8) else {
            throw UserError("无法取得 macOS 授权命令的结果。请刷新状态。")
        }
        return TunnelReply.decode(response, operation: operation)
    }

    static func authorizationProcess(arguments: [String]) -> Process {
        let child = Process()
        child.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
        child.arguments = ["-e", PrivilegedScripts.appleScript, "--"] + arguments
        child.environment = [
            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
            "HOME": FileManager.default.homeDirectoryForCurrentUser.path,
            "TMPDIR": NSTemporaryDirectory()
        ]
        child.standardInput = FileHandle.nullDevice
        child.standardError = FileHandle.nullDevice
        return child
    }
}
