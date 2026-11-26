import Darwin
import Foundation

final class WebsiteProxyProcess {
    let process: Process
    private let control: FileHandle

    init(_ process: Process, control: FileHandle) {
        self.process = process
        self.control = control
    }

    func stop() { try? control.close() }

    deinit { stop() }
}

enum WebsiteProxyService {
    private static let executable = AppSplitService.executable

    // The control pipe closes when the application exits, including after a crash.
    private static let supervisor = #"""
    exec 3<&0
    "$1" run -c "$2" </dev/null 3<&- &
    service=$!
    ( IFS= read -r unused <&3; kill "$service" 2>/dev/null ) &
    watcher=$!
    trap 'kill "$watcher" 2>/dev/null || :' EXIT
    wait "$service"
    """#

    static func start(profile: ConnectionProfile, rules: WebsiteRules) throws -> WebsiteProxyProcess {
        guard FileManager.default.isExecutableFile(atPath: executable) else {
            throw UserError("请先安装 ARM 版 sing-box。终端命令为 /opt/homebrew/bin/brew install sing-box")
        }
        try checkSystemRoutes()
        guard !proxyIsListening() else {
            throw UserError("本地分流端口 \(WebsiteRules.port) 已被占用。")
        }

        let json = try WebsiteProxyConfig.make(from: profile, rules: rules)
        let staged = try TunnelConfig.stage(json, named: "configuration.json")
        defer { try? FileManager.default.removeItem(at: staged.deletingLastPathComponent()) }

        let check = try launch(executable, ["check", "-c", staged.path])
        check.waitUntilExit()
        guard check.terminationStatus == 0 else {
            throw UserError("sing-box 未接受这份分流配置。请检查安装版本和线路配置。")
        }

        let control = Pipe()
        let process = try launch("/bin/sh", ["-c", supervisor, "--", executable, staged.path], stdin: control)
        let proxy = WebsiteProxyProcess(process, control: control.fileHandleForWriting)
        for _ in 0..<40 {
            guard process.isRunning else { break }
            if proxyIsListening(), process.isRunning { return proxy }
            Thread.sleep(forTimeInterval: 0.075)
        }
        proxy.stop()
        throw UserError("网站分流启动失败。请检查 sing-box 和本地端口。")
    }

    static func checkSystemRoutes() throws {
        let output = Pipe()
        let process = try launch("/usr/sbin/netstat", ["-rn", "-f", "inet"], stdout: output)
        let data = output.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        guard process.terminationStatus == 0 else { throw UserError("无法读取系统路由。") }

        let blocked = String(decoding: data, as: UTF8.self).split(separator: "\n").contains { row in
            let columns = row.split(whereSeparator: \.isWhitespace)
            guard columns.count > 3, columns[3].hasPrefix("utun") else { return false }
            return ["default", "0/0", "0.0.0.0/0", "0/1", "0.0.0.0/1", "128.0/1", "128.0.0.0/1"]
                .contains(String(columns[0]))
        }
        guard !blocked else {
            throw UserError("请先断开当前全局 VPN，再启动分流。")
        }
    }

    private static func launch(_ executable: String, _ arguments: [String],
                               stdin: Any = FileHandle.nullDevice,
                               stdout: Any = FileHandle.nullDevice) throws -> Process {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = arguments
        process.environment = ["PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL": "C"]
        process.standardInput = stdin
        process.standardOutput = stdout
        process.standardError = FileHandle.nullDevice
        do {
            try process.run()
            return process
        } catch {
            throw UserError("无法启动本地分流组件。")
        }
    }

    private static func proxyIsListening() -> Bool {
        let socket = Darwin.socket(AF_INET, SOCK_STREAM, 0)
        guard socket >= 0 else { return false }
        defer { close(socket) }
        var address = sockaddr_in()
        address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        address.sin_family = sa_family_t(AF_INET)
        address.sin_port = WebsiteRules.port.bigEndian
        address.sin_addr = in_addr(s_addr: inet_addr("127.0.0.1"))
        return withUnsafePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.connect(socket, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) == 0
            }
        }
    }
}
