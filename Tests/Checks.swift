import CryptoKit
import Darwin
import Foundation

@main
struct Checks {
    static func check(_ condition: Bool, _ label: String) throws {
        if !condition { throw UserError("自测失败：\(label)") }
    }

    static func run(_ path: String, _ arguments: [String], input: Data? = nil) throws -> String {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: path)
        process.arguments = arguments
        process.environment = [
            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
            "LC_ALL": "C",
            "TMPDIR": NSTemporaryDirectory()
        ]
        let output = Pipe()
        let stdin = Pipe()
        process.standardOutput = output
        process.standardInput = input == nil ? FileHandle.nullDevice : stdin
        try process.run()
        if let input {
            try stdin.fileHandleForWriting.write(contentsOf: input)
            try stdin.fileHandleForWriting.close()
        }
        let bytes = output.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        try check(process.terminationStatus == 0, path)
        return String(decoding: bytes, as: UTF8.self)
    }

    static func main() throws {
        let fm = FileManager.default
        let fixture = fm.temporaryDirectory.appendingPathComponent("wg-tests-\(UUID().uuidString)")
        try fm.createDirectory(at: fixture, withIntermediateDirectories: false,
                               attributes: [.posixPermissions: 0o700])
        defer { try? fm.removeItem(at: fixture) }

        let key = Curve25519.KeyAgreement.PrivateKey()
        let localPrivate = key.rawRepresentation.base64EncodedString()
        let localPublic = key.publicKey.rawRepresentation.base64EncodedString()
        let peer = Curve25519.KeyAgreement.PrivateKey().publicKey.rawRepresentation.base64EncodedString()
        let contents = "[Interface]\r\nPrivateKey = \(localPrivate)\r\n[Peer]\r\nPublicKey = \(peer)\r\n"
        let original = fixture.appendingPathComponent("mac.conf")
        let unusual = fixture.appendingPathComponent("空 格 ' & $(exit 99).conf")
        try Data(contents.utf8).write(to: original)
        try Data(contents.utf8).write(to: unusual)
        let config = try TunnelConfig.load(original)
        let alternate = try TunnelConfig.load(unusual)
        try check(config.name == "mac", "沿用标准接口名")
        try check(alternate.name.hasPrefix("wg-") && alternate.name.count == 15, "特殊文件名转换")
        try check(config.identity == alternate.identity, "同一配置身份")
        try check(config.mutationError == nil, "CRLF 配置")
        try check(config.identity == TunnelConfig.digest(Data("\(localPublic)\n\(peer)".utf8)), "公钥指纹")
        try checkWebsiteSplit(in: fixture, privateKey: localPrivate, peer: peer)
        try checkReality(in: fixture)
        try checkConnectionPreferences()
        if fm.isExecutableFile(atPath: "/opt/homebrew/bin/wg") {
            let derived = try run("/opt/homebrew/bin/wg", ["pubkey"], input: Data("\(localPrivate)\n".utf8))
            try check(derived == localPublic + "\n", "与 ARM WireGuard 公钥计算一致")
        }

        let snapshot = try alternate.stage()
        defer { try? fm.removeItem(at: snapshot.deletingLastPathComponent()) }
        try check(try Data(contentsOf: snapshot) == alternate.data, "快照与原内容一致")
        let attrs = try fm.attributesOfItem(atPath: snapshot.path)
        try check(attrs[.posixPermissions] as? Int == 0o600, "私有快照权限")
        let directoryAttrs = try fm.attributesOfItem(atPath: snapshot.deletingLastPathComponent().path)
        try check(directoryAttrs[.posixPermissions] as? Int == 0o700, "私有目录权限")

        for directive in ["preUP", "PostUp", "PreDown", "POSTDOWN", "SaveConfig"] {
            try Data((contents + "\t\(directive) \t = true # ignored comment\r\n").utf8).write(to: original)
            let checked = try TunnelConfig.load(original)
            try check(checked.mutationError != nil, "拦截 \(directive)")
        }
        try Data((contents + "SaveConfig = FALSE\n").utf8).write(to: original)
        let disabledSave = try TunnelConfig.load(original)
        try check(disabledSave.mutationError == nil, "允许 SaveConfig=false")
        try Data((contents + "Pre\u{0}Up = true").utf8).write(to: original)
        do {
            _ = try TunnelConfig.load(original)
            throw UserError("自测失败：接受了 NUL")
        } catch let error as UserError {
            try check(error.message.contains("UTF-8"), "拒绝 NUL")
        }

        let zero = TunnelReply.decode("OK\nactive\nh 0\nt 1 2\n", operation: .status)
        guard case .active(let waiting) = zero.state else { throw UserError("缺少等待握手状态") }
        try check(waiting.handshake == nil && !waiting.hasRecentHandshake(at: .now), "零握手不算连通")

        let recent = TunnelReply.decode("OK\nactive\nh 1000\nh 1010\nt 5 7\nt 9 11\n", operation: .status)
        guard case .active(let metrics) = recent.state else { throw UserError("缺少正常状态") }
        try check(metrics.received == 14 && metrics.sent == 18 && metrics.peers == 2, "流量累加")
        try check(metrics.hasRecentHandshake(at: Date(timeIntervalSince1970: 1190)), "最新握手")
        try check(!metrics.hasRecentHandshake(at: Date(timeIntervalSince1970: 1191)), "过期握手")
        try check(!metrics.hasRecentHandshake(at: Date(timeIntervalSince1970: 1009)), "未来握手")
        try check(TunnelReply.decode("OK\nactive\nh 1\nt malformed 1", operation: .status).state == .unknown,
                  "拒绝非数字状态")
        try check(TunnelReply.decode("OK\nactive\nh 1", operation: .status).state == .unknown,
                  "拒绝不完整状态")
        let later = TunnelReply.decode("OK\nactive\nh 1000\nh 1010\nt 10 14\nt 9 11\n", operation: .status)
        guard case .active(let updated) = later.state else { throw UserError("缺少后续流量快照") }
        try check(updated.handshake == metrics.handshake && updated.received == 19 && updated.sent == 25,
                  "握手不变时可读取新的收发量")
        guard case .paused = TunnelClient.observe(config.reference) else {
            throw UserError("无现有授权时应暂停自动刷新")
        }
        try check(TunnelReply.decode("CANCELLED", operation: .down).cancelled, "授权取消")
        try check(TunnelReply.decode("COMMAND_FAILED\ninactive", operation: .up).message != nil, "连接失败")

        let reachable = NetworkDiagnosis.Probe(name: "fixture", code: 0, http: 403, seconds: 0.5)
        let timeout = NetworkDiagnosis.Probe(name: "fixture", code: 28, http: 0, seconds: 8)
        let dnsFailure = NetworkDiagnosis.Probe(name: "fixture", code: 6, http: 0, seconds: 0)
        try check(reachable.reachable, "HTTP 拒绝页面仍说明网络可达")
        try check(NetworkDiagnosis.summarize(ip: reachable, domain: dnsFailure).contains("检查 DNS"),
                  "域名故障和 IP 故障分别诊断")
        try check(NetworkDiagnosis.summarize(ip: timeout, domain: reachable).contains("Gemini 可达"),
                  "单探测失败不判定整体断网")
        try check(NetworkDiagnosis.summarize(ip: timeout, domain: timeout).contains("两个 HTTPS 探测均失败"),
                  "两个请求失败才提示链路检查")

        for script in [PrivilegedScripts.bootstrap, PrivilegedScripts.worker, SessionScripts.bootstrap] {
            _ = try run("/bin/bash", ["-n", "-c", script])
        }
        _ = try run("/usr/bin/perl", ["-c", "-e", SessionScripts.server])
        _ = try run("/usr/bin/perl", ["-c", "-e", SessionScripts.appSplitServer])
        let apple = PrivilegedScripts.appleScript.replacingOccurrences(of: " with administrator privileges", with: "")
        let probe = "printf '%s' \"$1\""
        let quoted = try run("/usr/bin/osascript", ["-e", apple, "--", probe, "--", unusual.path])
        try check(quoted == unusual.path + "\n", "AppleScript 到 Bash 参数转义")
        let compiled = fixture.appendingPathComponent("authorization.scpt")
        _ = try run("/usr/bin/osacompile", ["-o", compiled.path, "-e", PrivilegedScripts.appleScript])

        print("通过：配置与网站分流、授权脚本和转义、快照权限、握手与流量、失败和取消。")
    }

    private static func tryCheckRules() throws -> WebsiteRules {
        let rules = try WebsiteRules("EXAMPLE.com.\nstatic.example.net，example.com")
        try check(rules.domains == ["example.com", "static.example.net"], "分流域名标准化")
        for invalid in ["https://example.com", "127.0.0.1", "example.com:443", "not..valid"] {
            try check((try? WebsiteRules(invalid)) == nil, "拒绝无效分流域名")
        }
        return rules
    }

    private static func tryCheckConfig(_ json: Data) throws {
        let decoded = try JSONSerialization.jsonObject(with: json) as? [String: Any]
        guard let inbounds = decoded?["inbounds"] as? [[String: Any]],
              let route = decoded?["route"] as? [String: Any],
              let rules = route["rules"] as? [[String: Any]],
              let dns = decoded?["dns"] as? [String: Any],
              let servers = dns["servers"] as? [[String: Any]] else {
            throw UserError("缺少分流配置")
        }
        try check(inbounds.first?["listen"] as? String == "127.0.0.1", "分流只监听本机")
        try check(rules.first?["outbound"] as? String == "direct"
                  && rules.first?["domain_suffix"] as? [String] == ["example.com", "static.example.net"],
                  "指定域名优先直连")
        try check(route["final"] as? String == "vpn" && rules.last?["server"] as? String == "vpn-dns"
                  && servers.last?["detour"] as? String == "vpn",
                  "其他网站和 DNS 使用 WireGuard")
    }

    private static func checkWebsiteSplit(in fixture: URL, privateKey: String, peer: String) throws {
        let rules = try tryCheckRules()
        let profile = fixture.appendingPathComponent("split.conf")
        let contents = """
        [Interface]
        PrivateKey = \(privateKey)
        Address = 10.66.0.2/32
        DNS = 9.9.9.9
        [Peer]
        PublicKey = \(peer)
        Endpoint = 192.0.2.1:51820
        AllowedIPs = 0.0.0.0/0
        """
        try Data(contents.utf8).write(to: profile)
        let config = try TunnelConfig.load(profile)
        let generated = try WebsiteProxyConfig.make(from: config, rules: rules)
        try tryCheckConfig(generated)
        let app = URL(fileURLWithPath: "/System/Applications/Utilities/Terminal.app")
        let appSplit = try WebsiteProxyConfig.makeAppSplit(from: config, directApps: [app])
        let options = try JSONSerialization.jsonObject(with: appSplit) as? [String: Any]
        let inbounds = options?["inbounds"] as? [[String: Any]]
        let route = options?["route"] as? [String: Any]
        let appRules = route?["rules"] as? [[String: Any]]
        try check(inbounds?.first?["type"] as? String == "tun"
                  && route?["auto_detect_interface"] as? Bool == true
                  && route?["final"] as? String == "vpn"
                  && appRules?.last?["outbound"] as? String == "direct"
                  && appRules?.last?["process_path_regex"] as? [String]
                      == ["^/System/Applications/Utilities/Terminal\\.app/Contents/"],
                  "系统分流按 App 路径直连，其余走 VPN")
        if let executable = ProcessInfo.processInfo.environment["WIREGUARD_TEST_SING_BOX"] {
            _ = try run(executable, ["check", "-c", "/dev/stdin"], input: appSplit)
        }
        if FileManager.default.isExecutableFile(atPath: "/opt/homebrew/bin/sing-box") {
            let staged = try TunnelConfig.stage(generated, named: "configuration.json")
            defer { try? FileManager.default.removeItem(at: staged.deletingLastPathComponent()) }
            _ = try run("/opt/homebrew/bin/sing-box", ["check", "-c", staged.path])
        }
    }

    private static func checkConnectionPreferences() throws {
        let suite = "wireguard-tests.\(UUID())"
        guard let defaults = UserDefaults(suiteName: suite) else { throw UserError("无法创建偏好测试域") }
        defer { defaults.removePersistentDomain(forName: suite) }
        let preferences = ConnectionPreferences(defaults: defaults)
        let app = URL(fileURLWithPath: "/System/Applications/Utilities/Terminal.app")

        try check(preferences.mode == .global, "无历史名单时选择全局 IPv4")
        defaults.set(try JSONEncoder().encode([app.path]), forKey: "directAppPaths")
        try check(preferences.directApps == [app] && preferences.mode == .appSplit, "沿用旧版直连名单")
        for line in ConnectionLine.allCases {
            try check(preferences.mode.start(on: line, directApps: preferences.directApps) == .singBox(directApps: [app]),
                      "App 分流模式向两条线路传入已保存的名单")
            try check(preferences.mode.start(on: line, directApps: []) == .singBox(directApps: []),
                      "空名单不会变成全局连接")
        }
        preferences.mode = .global
        try check(preferences.mode.start(on: .wireGuard, directApps: preferences.directApps) == .wireGuard,
                  "WireGuard 全局连接使用原生线路")
        try check(preferences.mode.start(on: .reality, directApps: preferences.directApps) == .singBox(directApps: nil),
                  "REALITY 全局连接不应用直连名单")
        let reopened = ConnectionPreferences(defaults: UserDefaults(suiteName: suite)!)
        try check(reopened.mode == .global && reopened.directApps == [app], "重开后保留明确选择的模式和名单")
    }

    private static func checkReality(in fixture: URL) throws {
        let profileURL = fixture.appendingPathComponent("reality.conf")
        let profile = ConnectionProfile(line: .reality, url: profileURL)
        let config: [String: Any] = [
            "inbounds": [["type": "mixed", "listen": "0.0.0.0", "listen_port": 8888]],
            "outbounds": [[
                "type": "vless", "server": "192.0.2.9", "server_port": 443,
                "uuid": UUID().uuidString, "flow": "xtls-rprx-vision",
                "tls": [
                    "enabled": true, "server_name": "www.example.com",
                    "utls": ["enabled": true, "fingerprint": "chrome"],
                    "reality": ["enabled": true, "short_id": "0123456789abcdef",
                                "public_key": String(repeating: "A", count: 43)]
                ]
            ]],
            "route": ["final": "direct"]
        ]
        try JSONSerialization.data(withJSONObject: config).write(to: profileURL)
        let app = URL(fileURLWithPath: "/System/Applications/Utilities/Terminal.app")
        let global = try WebsiteProxyConfig.makeGlobalReality(from: profileURL)
        let apps = try WebsiteProxyConfig.makeAppSplit(from: profile, directApps: [app])
        let sites = try WebsiteProxyConfig.make(from: profile, rules: try tryCheckRules())
        try tryCheckConfig(sites)
        for data in [global, apps, sites] {
            let document = try JSONSerialization.jsonObject(with: data) as? [String: Any]
            let outbound = (document?["outbounds"] as? [[String: Any]])?.first
            let route = document?["route"] as? [String: Any]
            try check(outbound?["type"] as? String == "vless" && outbound?["server_port"] as? Int == 443
                        && route?["final"] as? String == "vpn" && document?["endpoints"] == nil,
                      "REALITY 使用 TCP 出站，丢弃外部配置的路由")
            if FileManager.default.isExecutableFile(atPath: "/opt/homebrew/bin/sing-box") {
                let staged = try TunnelConfig.stage(data, named: "configuration.json")
                defer { try? FileManager.default.removeItem(at: staged.deletingLastPathComponent()) }
                _ = try run("/opt/homebrew/bin/sing-box", ["check", "-c", staged.path])
            }
        }
        let globalConfig = try JSONSerialization.jsonObject(with: global) as? [String: Any]
        let globalInbounds = globalConfig?["inbounds"] as? [[String: Any]]
        let globalRoute = globalConfig?["route"] as? [String: Any]
        try check(globalInbounds?.count == 1 && globalInbounds?.first?["type"] as? String == "tun"
                    && globalRoute?["find_process"] as? Bool == false,
                  "REALITY 全局仅创建应用自己的虚拟网卡，不继承配置的监听器")
        try Data(#"{"outbounds":[{"type":"vless","server":"192.0.2.9"}]}"#.utf8).write(to: profileURL)
        try check((try? RealityProfile.outbound(at: profileURL)) == nil, "拒绝缺少 REALITY 凭据的配置")
    }
}
