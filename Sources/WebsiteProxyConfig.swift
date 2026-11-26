import Foundation
import Network

enum WebsiteProxyConfig {
    static let tunIPv4Address = "172.19.255.1"

    private struct Transport {
        var endpoints: [[String: Any]] = []
        var outbounds: [[String: Any]] = []
        let dns: [String: Any]
    }

    static func make(from config: TunnelConfig, rules: WebsiteRules,
                     port: UInt16 = WebsiteRules.port) throws -> Data {
        try makeWebsite(transport: wireGuard(config), rules: rules, port: port)
    }

    static func make(from profile: ConnectionProfile, rules: WebsiteRules) throws -> Data {
        try makeWebsite(transport: transport(for: profile), rules: rules, port: WebsiteRules.port)
    }

    private static func makeWebsite(transport: Transport, rules: WebsiteRules, port: UInt16) throws -> Data {
        try make(transport: transport,
                 inbound: ["type": "socks", "listen": "127.0.0.1", "listen_port": port], rules: [
                    ["domain_suffix": rules.domains, "action": "route", "outbound": "direct"],
                    ["action": "resolve", "server": "vpn-dns", "strategy": "ipv4_only"]
                 ])
    }

    static func makeAppSplit(from config: TunnelConfig, directApps: [URL]) throws -> Data {
        try makeAppSplit(transport: wireGuard(config), directApps: directApps)
    }

    static func makeAppSplit(from profile: ConnectionProfile, directApps: [URL]) throws -> Data {
        try makeAppSplit(transport: transport(for: profile), directApps: directApps)
    }

    static func makeGlobalReality(from url: URL) throws -> Data {
        let profile = ConnectionProfile(line: .reality, url: url)
        return try makeTUN(transport: transport(for: profile), processPatterns: [])
    }

    private static func makeAppSplit(transport: Transport, directApps: [URL]) throws -> Data {
        guard !directApps.isEmpty else { throw UserError("请至少选择一个直连 App。") }
        let patterns = try directApps.map { url in
            let app = url.resolvingSymlinksInPath()
            guard app.isFileURL, app.pathExtension.lowercased() == "app",
                  let executable = Bundle(url: app)?.executableURL,
                  FileManager.default.isExecutableFile(atPath: executable.path) else {
                throw UserError("找不到可用的「\(url.deletingPathExtension().lastPathComponent)」，请在直连名单中重新添加或移除。")
            }
            return "^" + app.path.reduce(into: "") { pattern, character in
                if #"\.+*?()|[]{}^$"#.contains(character) { pattern.append("\\") }
                pattern.append(character)
            } + "/Contents/"
        }
        return try makeTUN(transport: transport, processPatterns: Array(Set(patterns)).sorted())
    }

    private static func makeTUN(transport: Transport, processPatterns: [String]) throws -> Data {
        var rules: [[String: Any]] = [["port": 53, "action": "hijack-dns"]]
        if !processPatterns.isEmpty {
            rules.append(["process_path_regex": processPatterns, "action": "route", "outbound": "direct"])
        }
        let inbound: [String: Any] = [
            "type": "tun", "address": ["\(tunIPv4Address)/30"], "auto_route": true
        ]
        return try make(transport: transport, inbound: inbound, rules: rules, tun: true,
                        findProcess: !processPatterns.isEmpty)
    }

    private static func transport(for profile: ConnectionProfile) throws -> Transport {
        switch profile.line {
        case .wireGuard:
            return try wireGuard(TunnelConfig.load(profile.url))
        case .reality:
            return Transport(outbounds: [try RealityProfile.outbound(at: profile.url)], dns: [
                "type": "https", "tag": "vpn-dns", "server": "1.1.1.1", "detour": "vpn"
            ])
        }
    }

    private static func wireGuard(_ config: TunnelConfig) throws -> Transport {
        if let error = config.mutationError { throw error }
        let (interface, peer) = try readFields(config.data)

        guard let privateKey = interface["privatekey"],
              let publicKey = peer["publickey"], Data(base64Encoded: publicKey)?.count == 32,
              let endpoint = peer["endpoint"],
              let address = URLComponents(string: "wireguard://" + endpoint),
              let host = address.host, !host.isEmpty,
              let remotePort = address.port, (1...65535).contains(remotePort),
              address.user == nil, address.password == nil, address.path.isEmpty,
              address.query == nil, address.fragment == nil,
              list(peer["allowedips"]).contains("0.0.0.0/0") else {
            throw UserError("分流需要一个有效的 WireGuard 对端，并允许 IPv4 全部网段（0.0.0.0/0）。")
        }

        let localAddresses = list(interface["address"]).filter { cidr in
            let parts = cidr.split(separator: "/", omittingEmptySubsequences: false)
            return parts.count == 2 && IPv4Address(String(parts[0])) != nil
                && Int(parts[1]).map { (0...32).contains($0) } == true
        }
        guard !localAddresses.isEmpty else { throw UserError("配置需要一个 IPv4 隧道地址。") }
        let endpointHost = host.hasPrefix("[") && host.hasSuffix("]")
            ? String(host.dropFirst().dropLast()) : host
        guard IPv4Address(endpointHost) != nil || IPv6Address(endpointHost) != nil
                || WebsiteRules.hostname(endpointHost) != nil else {
            throw UserError("WireGuard 对端地址格式无效。")
        }

        var wireguardPeer: [String: Any] = [
            "address": endpointHost, "port": remotePort,
            "public_key": publicKey, "allowed_ips": ["0.0.0.0/0"]
        ]
        if let key = peer["presharedkey"] {
            guard Data(base64Encoded: key)?.count == 32 else {
                throw UserError("配置中的预共享密钥格式无效。")
            }
            wireguardPeer["pre_shared_key"] = key
        }
        if let value = peer["persistentkeepalive"], value.lowercased() != "off" {
            guard let interval = UInt16(value) else { throw UserError("保活间隔格式无效。") }
            wireguardPeer["persistent_keepalive_interval"] = interval
        }

        var wireguard: [String: Any] = [
            "type": "wireguard", "tag": "vpn", "system": false,
            "address": localAddresses, "private_key": privateKey,
            "peers": [wireguardPeer], "domain_resolver": "local-dns"
        ]
        if let value = interface["mtu"] {
            guard let mtu = UInt16(value), mtu > 0 else { throw UserError("MTU 格式无效。") }
            wireguard["mtu"] = mtu
        }

        let dns = list(interface["dns"]).first { IPv4Address($0) != nil } ?? "1.1.1.1"
        return Transport(endpoints: [wireguard], dns: [
            "type": "udp", "tag": "vpn-dns", "server": dns, "detour": "vpn"
        ])
    }

    private static func make(transport: Transport, inbound: [String: Any], rules: [[String: Any]],
                             tun: Bool = false, findProcess: Bool = false) throws -> Data {
        var configuration: [String: Any] = [
            "log": ["disabled": true],
            "inbounds": [inbound],
            "outbounds": transport.outbounds + [["type": "direct", "tag": "direct", "domain_resolver": "local-dns"]],
            "dns": [
                "servers": [["type": "local", "tag": "local-dns"], transport.dns],
                "final": tun ? "vpn-dns" : "local-dns"
            ],
            "route": [
                "rules": rules,
                "auto_detect_interface": tun,
                "find_process": findProcess,
                "final": "vpn"
            ]
        ]
        if !transport.endpoints.isEmpty { configuration["endpoints"] = transport.endpoints }
        return try JSONSerialization.data(withJSONObject: configuration, options: [.sortedKeys])
    }

    private static func readFields(_ data: Data) throws -> ([String: String], [String: String]) {
        var sections: [String: [String: String]] = [:]
        var section: String?
        for bytes in data.split(separator: 10) {
            let text = String(decoding: bytes.prefix { $0 != 35 }, as: UTF8.self)
                .trimmingCharacters(in: .whitespacesAndNewlines)
            if text.isEmpty { continue }
            if text.hasPrefix("[") {
                let name = text.lowercased()
                guard ["[interface]", "[peer]"].contains(name), sections[name] == nil else {
                    throw UserError("分流目前支持一组 Interface 和一组 Peer。")
                }
                sections[name] = [:]
                section = name
            } else if let section, let equal = text.firstIndex(of: "=") {
                let key = text[..<equal].trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
                let value = text[text.index(after: equal)...].trimmingCharacters(in: .whitespacesAndNewlines)
                if ["address", "dns", "allowedips"].contains(key), let previous = sections[section]?[key] {
                    sections[section]?[key] = previous + "," + value
                } else {
                    sections[section]?[key] = value
                }
            }
        }
        guard let interface = sections["[interface]"], let peer = sections["[peer]"] else {
            throw UserError("配置缺少 Interface 或 Peer 段。")
        }
        return (interface, peer)
    }

    private static func list(_ value: String?) -> [String] {
        (value ?? "").split(separator: ",").map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
    }
}
