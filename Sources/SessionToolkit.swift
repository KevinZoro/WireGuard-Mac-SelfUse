import Foundation

struct SessionTool {
    let name: String
    let data: Data

    var manifestItem: String { "\(name):\(TunnelConfig.digest(data))" }
}

enum SessionToolkit {
    private static let homebrew = "/opt/homebrew"
    // Darwin script from the reviewed ARM Homebrew wireguard-tools 1.0.20260223.
    // A changed script may introduce new dependencies outside the pinned tools.
    private static let reviewedQuick = "c6d3fa50abce6edf527ec512678f5a305ab0c76e0e6baeba647b80d7e4317f17"

    static func prepare() throws -> [SessionTool] {
        let otool = try developerTool("otool")
        let installNameTool = try developerTool("install_name_tool")
        let scratch = FileManager.default.temporaryDirectory
            .appendingPathComponent("wgc-toolkit-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: scratch, withIntermediateDirectories: false,
                                               attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: scratch) }

        var installed: [String: String] = [:]
        for name in ["wg", "wireguard-go", "bash", "wg-quick"] {
            try snapshot("\(homebrew)/bin/\(name)", into: scratch,
                         otool: otool, installNameTool: installNameTool, installed: &installed)
        }
        return try installed.keys.sorted().map { name in
            let data = try Data(contentsOf: scratch.appendingPathComponent(name))
            guard !data.isEmpty, data.count <= 32 * 1024 * 1024 else { throw unavailable }
            if name == "wg-quick", TunnelConfig.digest(data) != reviewedQuick { throw unavailable }
            return SessionTool(name: name, data: data)
        }
    }

    static func prepareAppSplit(executable: String, configuration: Data) throws -> [SessionTool] {
        guard !configuration.isEmpty, configuration.count <= 1024 * 1024 else {
            throw UserError("分流配置超出大小限制。")
        }
        let source = URL(fileURLWithPath: executable).resolvingSymlinksInPath()
        guard source.path.hasPrefix(homebrew + "/Cellar/sing-box/") else {
            throw UserError("请使用 ARM Homebrew 安装的 sing-box。")
        }
        let attributes = try source.resourceValues(forKeys: [.isRegularFileKey, .fileSizeKey])
        guard attributes.isRegularFile == true,
              let size = attributes.fileSize, (1...(128 * 1024 * 1024)).contains(size) else {
            throw UserError("sing-box 文件无效。")
        }
        let scratch = try TunnelConfig.stage(Data(contentsOf: source), named: "sing-box")
        defer { try? FileManager.default.removeItem(at: scratch.deletingLastPathComponent()) }
        let data = try Data(contentsOf: scratch)
        let otool = try developerTool("otool")
        let architecture = try run("/usr/bin/lipo", ["-archs", scratch.path])
        guard !data.isEmpty, data.count <= 128 * 1024 * 1024,
              architecture.trimmingCharacters(in: .whitespacesAndNewlines) == "arm64",
              try !run(otool, ["-l", scratch.path]).contains("LC_DYLD_ENVIRONMENT"),
              try dependencies(otool, scratch).allSatisfy({
                  $0.hasPrefix("/usr/lib/") || $0.hasPrefix("/System/Library/")
              }) else {
            throw UserError("当前 sing-box 版本无法用系统授权安全启动。")
        }
        return [SessionTool(name: "sing-box", data: data),
                SessionTool(name: "app-split.json", data: configuration)]
    }

    private static var unavailable: UserError {
        UserError("当前工具链无法建立可复用的授权会话。")
    }

    private static func snapshot(_ source: String, into scratch: URL, otool: String,
                                 installNameTool: String, installed: inout [String: String]) throws {
        let original = URL(fileURLWithPath: source)
        let resolved = original.resolvingSymlinksInPath()
        let name = original.lastPathComponent
        guard resolved.path.hasPrefix(homebrew + "/"),
              name.range(of: #"\A[a-zA-Z0-9_+-][a-zA-Z0-9._+-]{0,79}\z"#, options: .regularExpression) != nil else {
            throw unavailable
        }
        if let existing = installed[name] {
            guard existing == resolved.path else { throw unavailable }
            return
        }
        guard installed.count < 32,
              (try resolved.resourceValues(forKeys: [.isRegularFileKey])).isRegularFile == true else {
            throw unavailable
        }
        let target = scratch.appendingPathComponent(name)
        try FileManager.default.copyItem(at: resolved, to: target)
        installed[name] = resolved.path
        if name == "wg-quick" { return }

        let architecture = try run("/usr/bin/lipo", ["-archs", target.path])
            .trimmingCharacters(in: .whitespacesAndNewlines)
        guard architecture == "arm64" else { throw unavailable }
        guard try !run(otool, ["-l", target.path]).contains("LC_DYLD_ENVIRONMENT") else {
            throw unavailable
        }

        let linked = try dependencies(otool, target)
        var edits = [String]()
        for dependency in linked {
            if dependency.hasPrefix("/usr/lib/") || dependency.hasPrefix("/System/Library/") { continue }
            // The upstream route monitor can outlive the authorization session.
            // wg and wireguard-go must remain independent of session libraries.
            guard name != "wg", name != "wireguard-go", dependency.hasPrefix(homebrew + "/") else {
                throw unavailable
            }
            let depName = URL(fileURLWithPath: dependency).lastPathComponent
            if depName == name {
                edits += ["-id", "@loader_path/\(name)"]
            } else {
                try snapshot(dependency, into: scratch,
                             otool: otool, installNameTool: installNameTool, installed: &installed)
                edits += ["-change", dependency, "@loader_path/\(depName)"]
            }
        }
        if !edits.isEmpty {
            try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: target.path)
            _ = try run(installNameTool, edits + [target.path])
            _ = try run("/usr/bin/codesign", ["--force", "--sign", "-", target.path])
        }
    }

    private static func dependencies(_ otool: String, _ file: URL) throws -> [String] {
        let lines = try run(otool, ["-L", file.path]).split(separator: "\n")
        guard lines.count > 1 else { throw unavailable }
        return try lines.dropFirst().map { line in
            guard let end = line.range(of: " (compatibility version ") else { throw unavailable }
            return line[..<end.lowerBound].trimmingCharacters(in: .whitespaces)
        }
    }

    private static func developerTool(_ name: String) throws -> String {
        let path = try run("/usr/bin/xcrun", ["--find", name])
            .trimmingCharacters(in: .whitespacesAndNewlines)
        guard path.hasPrefix("/") else { throw unavailable }
        return path
    }

    private static func run(_ path: String, _ arguments: [String]) throws -> String {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: path)
        process.arguments = arguments
        process.environment = ["PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL": "C"]
        let pipe = Pipe()
        process.standardInput = FileHandle.nullDevice
        process.standardOutput = pipe
        process.standardError = FileHandle.nullDevice
        try process.run()
        let output = pipe.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        guard process.terminationStatus == 0, let text = String(data: output, encoding: .utf8) else {
            throw unavailable
        }
        return text
    }
}
