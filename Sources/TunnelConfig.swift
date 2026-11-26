import CryptoKit
import Darwin
import Foundation

struct UserError: LocalizedError, Sendable {
    let message: String
    init(_ message: String) { self.message = message }
    var errorDescription: String? { message }
}

struct TunnelReference: Sendable {
    let name: String
    let identity: String
}

struct TunnelConfig: Sendable {
    static let maxBytes = 131_072

    let url: URL
    let name: String
    let data: Data
    let identity: String
    let mutationError: UserError?

    var reference: TunnelReference { TunnelReference(name: name, identity: identity) }

    static func load(_ url: URL) throws -> TunnelConfig {
        guard url.isFileURL, url.pathExtension.lowercased() == "conf" else {
            throw UserError("请选择一个 .conf 配置文件。")
        }
        let data = try readProfile(url)

        return try parse(data, at: url)
    }

    static func readProfile(_ url: URL) throws -> Data {
        guard url.isFileURL else { throw UserError("请选择本机配置文件。") }
        let fd = open(url.path, O_RDONLY | O_NONBLOCK | O_CLOEXEC)
        guard fd >= 0 else {
            throw UserError("无法读取配置文件。请确认文件存在，并在需要时允许应用访问「下载」文件夹。")
        }
        let file = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
        defer { try? file.close() }
        var info = stat()
        guard fstat(fd, &info) == 0, info.st_mode & S_IFMT == S_IFREG,
              info.st_size <= maxBytes,
              let data = try? file.read(upToCount: maxBytes + 1),
              data.count <= maxBytes, !data.contains(0),
              String(data: data, encoding: .utf8) != nil else {
            throw UserError("配置须为 128 KiB 以内的 UTF-8 普通文件。")
        }
        return data
    }

    private static func parse(_ data: Data, at url: URL) throws -> TunnelConfig {
        var section = ""
        var privateKey: Data?
        var peerKeys = Set<String>()
        var mutationError: UserError?
        // Match wg-quick's LF-delimited lines, comment removal and ASCII case-insensitive keys.
        for bytes in data.split(separator: 10) {
            let uncommented = bytes.prefix { $0 != 35 }
            let line = String(decoding: uncommented, as: UTF8.self)
                .trimmingCharacters(in: .whitespacesAndNewlines)
            let fields = line.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
            guard let field = fields.first else { continue }
            let key = field.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
            if key.hasPrefix("[") { section = key }
            guard fields.count == 2 else { continue }
            let value = fields[1].trimmingCharacters(in: .whitespacesAndNewlines)
            switch key {
            case "preup", "postup", "predown", "postdown":
                mutationError = UserError("此配置含命令钩子。首版只操作无命令钩子的配置。")
            case "saveconfig" where value.lowercased() != "false":
                mutationError = mutationError ?? UserError("此配置启用了 SaveConfig。首版只接受关闭 SaveConfig 的配置。")
            case "privatekey" where section == "[interface]":
                guard privateKey == nil, let keyData = Data(base64Encoded: value), keyData.count == 32 else {
                    throw UserError("配置需要一个有效的 Interface 私钥。")
                }
                privateKey = keyData
            case "publickey" where section == "[peer]":
                guard let keyData = Data(base64Encoded: value), keyData.count == 32 else {
                    throw UserError("配置含无效的对端公钥。")
                }
                peerKeys.insert(keyData.base64EncodedString())
            default:
                break
            }
        }

        guard let privateKey, privateKey.contains(where: { $0 != 0 }),
              let key = try? Curve25519.KeyAgreement.PrivateKey(rawRepresentation: privateKey) else {
            throw UserError("未找到可用的 Interface 私钥。")
        }
        let publicKey = key.publicKey.rawRepresentation.base64EncodedString()
        let base = url.deletingPathExtension().lastPathComponent
        let canUseBase = url.pathExtension == "conf"
            && base.range(of: #"\A[a-zA-Z0-9_=+.-]{1,15}\z"#, options: .regularExpression) != nil
        let name = canUseBase ? base : "wg-" + digest(Data(url.standardizedFileURL.path.utf8)).prefix(12)
        let peers = peerKeys.sorted().joined(separator: "\n")
        let identity = digest(Data("\(publicKey)\n\(peers)".utf8))
        return TunnelConfig(url: url, name: name, data: data, identity: identity, mutationError: mutationError)
    }

    static func digest(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    func stage() throws -> URL {
        try Self.stage(data, named: "configuration")
    }

    static func stage(_ data: Data, named filename: String) throws -> URL {
        let location = FileManager.default.temporaryDirectory.appendingPathComponent("personal-wg.XXXXXXXX")
        var template = Array(location.path.utf8CString)
        guard let directory = template.withUnsafeMutableBufferPointer({ buffer -> String? in
            guard let base = buffer.baseAddress, mkdtemp(base) != nil else { return nil }
            return String(cString: base)
        }) else { throw UserError("无法创建私有临时目录。") }

        let dir = URL(fileURLWithPath: directory, isDirectory: true)
        do {
            let url = dir.appendingPathComponent(filename)
            let fd = open(url.path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0o600)
            guard fd >= 0 else { throw UserError("无法创建私有临时文件。") }
            let file = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
            defer { try? file.close() }
            try file.write(contentsOf: data)
            return url
        } catch {
            try? FileManager.default.removeItem(at: dir)
            throw UserError("无法写入私有临时文件。")
        }
    }
}
