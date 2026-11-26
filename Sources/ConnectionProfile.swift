import Foundation
import Network

enum ConnectionLine: String, CaseIterable, Sendable {
    case wireGuard
    case reality

    var title: String {
        switch self {
        case .wireGuard: return "WireGuard"
        case .reality: return "VLESS + REALITY"
        }
    }
}

enum ConnectionMode: String, CaseIterable {
    case global
    case appSplit

    var title: String {
        switch self {
        case .global: "全局 IPv4"
        case .appSplit: "App 分流"
        }
    }

    func start(on line: ConnectionLine, directApps: [URL]) -> ConnectionStart {
        switch self {
        case .global: line == .wireGuard ? .wireGuard : .singBox(directApps: nil)
        case .appSplit: .singBox(directApps: directApps)
        }
    }
}

enum ConnectionStart: Equatable {
    case wireGuard
    case singBox(directApps: [URL]?)
}

struct ConnectionPreferences {
    var defaults = UserDefaults.standard

    var mode: ConnectionMode {
        get {
            let saved = defaults.string(forKey: "connectionMode").flatMap(ConnectionMode.init(rawValue:))
            return saved ?? (directApps.isEmpty ? .global : .appSplit)
        }
        nonmutating set { defaults.set(newValue.rawValue, forKey: "connectionMode") }
    }

    var directApps: [URL] {
        get {
            guard let data = defaults.data(forKey: "directAppPaths"),
                  let paths = try? JSONDecoder().decode([String].self, from: data) else { return [] }
            return paths.filter { $0.hasPrefix("/") }.map { URL(fileURLWithPath: $0) }
        }
        nonmutating set {
            defaults.set(try? JSONEncoder().encode(newValue.map(\.path)), forKey: "directAppPaths")
        }
    }
}

struct ConnectionProfile: Equatable, Sendable {
    let line: ConnectionLine
    let url: URL

    static let defaultRealityURL = FileManager.default.homeDirectoryForCurrentUser
        .appendingPathComponent("Library/Application Support/WireGuard Control/reality-client.conf")
}

enum RealityProfile {
    static func outbound(at url: URL) throws -> [String: Any] {
        let data = try TunnelConfig.readProfile(url)
        let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
        let candidates = (root?["outbounds"] as? [[String: Any]] ?? [])
            .filter { $0["type"] as? String == "vless" }
        guard candidates.count == 1, let source = candidates.first,
              let server = source["server"] as? String,
              IPv4Address(server) != nil || IPv6Address(server) != nil || WebsiteRules.hostname(server) != nil,
              let port = source["server_port"] as? Int, (1...65535).contains(port),
              let uuid = source["uuid"] as? String, UUID(uuidString: uuid) != nil,
              let tls = source["tls"] as? [String: Any], tls["enabled"] as? Bool == true,
              let name = tls["server_name"] as? String, let hostname = WebsiteRules.hostname(name),
              let reality = tls["reality"] as? [String: Any], reality["enabled"] as? Bool == true,
              let publicKey = reality["public_key"] as? String,
              publicKey.range(of: #"\A[A-Za-z0-9_-]{43}\z"#, options: .regularExpression) != nil,
              let shortID = reality["short_id"] as? String,
              shortID.range(of: #"\A(?:[A-Fa-f0-9]{2}){0,8}\z"#, options: .regularExpression) != nil else {
            throw UserError("请选择含一个有效 VLESS + REALITY 出站的 sing-box 客户端配置。")
        }
        let flow = source["flow"] as? String ?? ""
        guard flow.isEmpty || flow == "xtls-rprx-vision", source["transport"] == nil else {
            throw UserError("此线路支持直连 TCP，流控可留空或使用 xtls-rprx-vision。")
        }
        let utls = tls["utls"] as? [String: Any]
        let fingerprint = utls?["fingerprint"] as? String ?? "chrome"
        guard ["chrome", "firefox", "safari", "edge", "ios", "android", "random", "randomized"]
                .contains(fingerprint) else {
            throw UserError("REALITY 配置的 uTLS 指纹不受支持。")
        }
        // Rebuild only the fields used by the outbound. The imported file can
        // never supply listeners, routing rules or file paths to the root process.
        return [
            "type": "vless", "tag": "vpn", "server": server, "server_port": port,
            "uuid": uuid, "flow": flow, "domain_resolver": "local-dns",
            "tls": [
                "enabled": true, "server_name": hostname,
                "utls": ["enabled": true, "fingerprint": fingerprint],
                "reality": ["enabled": true, "public_key": publicKey, "short_id": shortID]
            ]
        ]
    }
}
