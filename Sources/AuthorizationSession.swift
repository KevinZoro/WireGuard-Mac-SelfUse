import Darwin
import Foundation

final class AuthorizationSession {
    enum Start {
        case connected(AuthorizationSession)
        case rejected(String)
    }

    private let socket: Int32
    private let child: Process

    private init(socket: Int32, child: Process) {
        self.socket = socket
        self.child = child
    }

    deinit { close(socket) }

    var process: Process { child }

    func stopAppSplit() {
        _ = shutdown(socket, SHUT_RDWR)
    }

    var isUsable: Bool {
        guard child.isRunning else { return false }
        var event = pollfd(fd: socket, events: Int16(POLLIN), revents: 0)
        return poll(&event, 1, 0) == 0
    }

    func run(_ action: Operation, config: TunnelConfig, staged: URL?) throws -> String {
        let path = staged.map { Data($0.path.utf8).base64EncodedString() } ?? ""
        let digest = staged.map { _ in TunnelConfig.digest(config.data) } ?? ""
        let reply = try request(action.rawValue, for: config.reference, path: path, digest: digest)
        return reply
    }

    func observe(_ reference: TunnelReference) throws -> String {
        try Self.setTimeouts(socket, seconds: 4)
        let reply = try request("observe", for: reference)
        try Self.setTimeouts(socket, seconds: 120)
        return reply
    }

    private func request(_ action: String, for reference: TunnelReference,
                         path: String = "", digest: String = "") throws -> String {
        let request = [action, reference.name, reference.identity, path, digest].joined(separator: "\t")
        try Self.writeFrame(Data(request.utf8), to: socket)
        let reply = try Self.readFrame(from: socket)
        guard let text = String(data: reply, encoding: .utf8) else { throw Self.interrupted }
        return text
    }

    static func start(tools: [SessionTool]) throws -> Start {
        try connect(tools: tools, script: SessionScripts.server, worker: PrivilegedScripts.worker)
    }

    static func startAppSplit(tools: [SessionTool]) throws -> Start {
        try connect(tools: tools, script: SessionScripts.appSplitServer, worker: "")
    }

    private static func connect(tools: [SessionTool], script: String, worker: String) throws -> Start {
        var template = Array("/private/tmp/wgc.XXXXXXXX".utf8CString)
        guard let directory = template.withUnsafeMutableBufferPointer({ buffer -> String? in
            guard let base = buffer.baseAddress, mkdtemp(base) != nil else { return nil }
            return String(cString: base)
        }) else { throw interrupted }
        defer { try? FileManager.default.removeItem(atPath: directory) }

        let path = directory + "/socket"
        let listener = Darwin.socket(AF_UNIX, SOCK_STREAM, 0)
        guard listener >= 0 else { throw interrupted }
        defer { close(listener) }
        try configure(listener)
        try bindSocket(listener, path: path)
        guard listen(listener, 4) == 0 else { throw interrupted }

        let child = TunnelClient.authorizationProcess(arguments: [
            SessionScripts.bootstrap, "--", script, worker,
            path, String(getpid()), String(getuid())
        ] + tools.map(\.manifestItem))
        let pipe = Pipe()
        child.standardOutput = pipe
        try child.run()

        while child.isRunning {
            var event = pollfd(fd: listener, events: Int16(POLLIN), revents: 0)
            let result = poll(&event, 1, 250)
            if result < 0 && errno == EINTR { continue }
            guard result >= 0 else { throw interrupted }
            guard result > 0 else { continue }
            let connection = accept(listener, nil, nil)
            guard connection >= 0 else {
                if errno == EINTR { continue }
                throw interrupted
            }
            var peerUID: uid_t = 0
            var peerGID: gid_t = 0
            guard getpeereid(connection, &peerUID, &peerGID) == 0, peerUID == 0 else {
                close(connection)
                continue
            }
            do {
                try configure(connection)
                for tool in tools {
                    try writeFrame(tool.data, to: connection)
                }
                let reply = try readFrame(from: connection)
                guard reply == Data("READY".utf8) else {
                    close(connection)
                    return .rejected(String(decoding: reply, as: UTF8.self))
                }
                return .connected(AuthorizationSession(socket: connection, child: child))
            } catch {
                close(connection)
                throw error
            }
        }
        let output = pipe.fileHandleForReading.readDataToEndOfFile()
        return .rejected(String(decoding: output, as: UTF8.self))
    }

    private static var interrupted: UserError {
        UserError("授权会话已中断。请先刷新状态，再决定是否重试。")
    }

    private static func configure(_ socket: Int32) throws {
        guard fcntl(socket, F_SETFD, FD_CLOEXEC) != -1 else { throw interrupted }
        var enable: Int32 = 1
        guard setsockopt(socket, SOL_SOCKET, SO_NOSIGPIPE, &enable,
                         socklen_t(MemoryLayout.size(ofValue: enable))) == 0 else { throw interrupted }
        try setTimeouts(socket, seconds: 120)
    }

    private static func setTimeouts(_ socket: Int32, seconds: Int) throws {
        var timeout = timeval(tv_sec: seconds, tv_usec: 0)
        let size = socklen_t(MemoryLayout.size(ofValue: timeout))
        guard setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, &timeout, size) == 0,
              setsockopt(socket, SOL_SOCKET, SO_SNDTIMEO, &timeout, size) == 0 else { throw interrupted }
    }

    private static func bindSocket(_ socket: Int32, path: String) throws {
        var address = sockaddr_un()
        address.sun_family = sa_family_t(AF_UNIX)
        let bytes = path.utf8CString
        guard bytes.count <= MemoryLayout.size(ofValue: address.sun_path) else { throw interrupted }
        withUnsafeMutableBytes(of: &address.sun_path) { storage in
            bytes.withUnsafeBytes { storage.copyBytes(from: $0) }
        }
        let length = MemoryLayout<sockaddr_un>.offset(of: \.sun_path)! + bytes.count
        address.sun_len = UInt8(length)
        let result = withUnsafePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.bind(socket, $0, socklen_t(length))
            }
        }
        guard result == 0 else { throw interrupted }
    }

    private static func writeFrame(_ data: Data, to socket: Int32) throws {
        var size = UInt32(data.count).bigEndian
        try withUnsafeBytes(of: &size) { try write($0, to: socket) }
        try data.withUnsafeBytes { try write($0, to: socket) }
    }

    private static func write(_ data: UnsafeRawBufferPointer, to socket: Int32) throws {
        guard let base = data.baseAddress else { return }
        var offset = 0
        while offset < data.count {
            let count = Darwin.send(socket, base.advanced(by: offset), data.count - offset, 0)
            if count < 0 && errno == EINTR { continue }
            guard count > 0 else { throw interrupted }
            offset += count
        }
    }

    private static func readFrame(from socket: Int32) throws -> Data {
        var size: UInt32 = 0
        try withUnsafeMutableBytes(of: &size) { try read($0, from: socket) }
        let count = Int(UInt32(bigEndian: size))
        guard count <= 2_000_000 else { throw interrupted }
        var data = Data(count: count)
        try data.withUnsafeMutableBytes { try read($0, from: socket) }
        return data
    }

    private static func read(_ data: UnsafeMutableRawBufferPointer, from socket: Int32) throws {
        guard let base = data.baseAddress else { return }
        var offset = 0
        while offset < data.count {
            let count = Darwin.recv(socket, base.advanced(by: offset), data.count - offset, 0)
            if count < 0 && errno == EINTR { continue }
            guard count > 0 else { throw interrupted }
            offset += count
        }
    }
}
