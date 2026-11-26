import Foundation
import Network

struct NetworkDiagnosis: Sendable {
    struct Probe: Sendable {
        let name: String
        let code: Int32
        let http: Int
        let seconds: Double

        var reachable: Bool { code == 0 && (100...599).contains(http) }

        var description: String {
            if reachable { return "\(name)：收到 HTTP \(http)，用时 \(String(format: "%.2f", seconds)) 秒" }
            let reason: String
            switch code {
            case 6: reason = "域名解析失败"
            case 7: reason = "无法建立连接"
            case 28: reason = "请求超时"
            case 35, 60: reason = "TLS 连接或证书校验失败"
            default: reason = "请求失败（代码 \(code)）"
            }
            return "\(name)：\(reason)"
        }
    }

    let summary: String
    let report: String

    static func collect(reference: TunnelReference?) async -> NetworkDiagnosis {
        let before = snapshot(reference)
        async let ip = Task.detached(priority: .utility) {
            probe("IPv4 HTTPS（Cloudflare）", url: "https://1.1.1.1/cdn-cgi/trace")
        }.value
        async let domain = Task.detached(priority: .utility) {
            probe("域名 HTTPS（Gemini）", url: "https://gemini.google.com/")
        }.value
        let (ipResult, domainResult) = await (ip, domain)
        let after = snapshot(reference)
        let summary = summarize(ip: ipResult, domain: domainResult)
        let version = Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "测试"
        let report = [
            "WireGuard 控制台网络诊断 v\(version)",
            "时间：\(Date().ISO8601Format())",
            "结论：\(summary)",
            ipResult.description,
            domainResult.description,
            "IPv4 路由：\(routeSummary())",
            "探测前：\(before)",
            "探测后：\(after)",
            "HTTPS 探测使用系统 IPv4 路由并绕过 HTTP/SOCKS 代理。",
            "HTTP 响应只证明目标可达，业务页面功能需另外确认。"
        ].joined(separator: "\n")
        return NetworkDiagnosis(summary: summary, report: report)
    }

    static func summarize(ip: Probe, domain: Probe) -> String {
        if ip.reachable && domain.reachable {
            return "本次 IPv4 HTTPS 和域名请求均有响应。"
        }
        if ip.reachable && domain.code == 6 {
            return "IPv4 HTTPS 可达，域名解析失败，需检查 DNS。"
        }
        if ip.reachable {
            return "IPv4 HTTPS 可达，Gemini 请求失败，需检查目标链路或浏览器。"
        }
        if domain.reachable {
            return "Gemini 可达，Cloudflare 探测失败，需结合实际网站判断。"
        }
        return "两个 HTTPS 探测均失败，需结合握手和路由检查本机网络及 VPN 链路。"
    }

    static func publicIPv4() -> String? {
        guard hasAppTunnelRoute() else { return nil }
        let result = command("/usr/bin/curl", [
            "--ipv4", "--noproxy", "*", "--fail", "--silent",
            "--connect-timeout", "4", "--max-time", "8", "https://api4.ipify.org"
        ])
        let address = result.output.trimmingCharacters(in: .whitespacesAndNewlines)
        return result.code == 0 && IPv4Address(address) != nil && hasAppTunnelRoute() ? address : nil
    }

    static func openAIHTTPSThroughTUN() -> Bool {
        guard hasAppTunnelRoute() else { return false }
        return probe("OpenAI HTTPS", url: "https://api.openai.com/v1/models").reachable
            && hasAppTunnelRoute()
    }

    private static func hasAppTunnelRoute() -> Bool {
        let route = command("/sbin/route", ["-n", "get", "1.1.1.1"])
        guard route.code == 0,
              let interface = route.output.split(separator: "\n").compactMap({ line -> String? in
                  let fields = line.split(whereSeparator: \.isWhitespace)
                  guard fields.count == 2, fields[0] == "interface:",
                        fields[1].range(of: #"\Autun[0-9]+\z"#, options: .regularExpression) != nil
                  else { return nil }
                  return String(fields[1])
              }).first else { return false }
        let info = command("/sbin/ifconfig", [interface])
        return info.code == 0 && info.output.range(of: #"(?m)^\s+inet 172\.19\.255\.1\s"#,
                                                   options: .regularExpression) != nil
    }

    private static func snapshot(_ reference: TunnelReference?) -> String {
        guard let reference else { return "尚未选择并读取隧道，握手和流量未采集" }
        switch TunnelClient.observe(reference) {
        case .paused: return "授权会话不可用，握手和流量未采集"
        case .skipped: return "查询繁忙或暂不可用"
        case .snapshot(.unknown): return "隧道状态未知"
        case .snapshot(.inactive): return "隧道未建立"
        case .snapshot(.conflict): return "接口身份与所选配置不匹配"
        case .snapshot(.active(let metrics)):
            let age = metrics.handshake.map { max(0, Int(Date().timeIntervalSince($0))) }
            let handshake = age.map { "\($0) 秒前" } ?? "尚无"
            return "接口已建立，最近握手 \(handshake)，接收 \(metrics.received) 字节，发送 \(metrics.sent) 字节"
        }
    }

    private static func probe(_ name: String, url: String) -> Probe {
        let result = command("/usr/bin/curl", [
            "--ipv4", "--noproxy", "*", "--head", "--silent",
            "--connect-timeout", "4", "--max-time", "8", "--output", "/dev/null",
            "--write-out", "%{http_code} %{time_total}", url
        ])
        let fields = result.output.split(whereSeparator: \.isWhitespace)
        guard fields.count == 2, let status = Int(fields[0]), let duration = Double(fields[1]) else {
            return Probe(name: name, code: result.code == 0 ? -1 : result.code, http: 0, seconds: 0)
        }
        return Probe(name: name, code: result.code, http: status, seconds: duration)
    }

    private static func routeSummary() -> String {
        let result = command("/usr/sbin/netstat", ["-rn", "-f", "inet"])
        guard result.code == 0 else { return "无法读取" }
        let routes = result.output.split(separator: "\n").compactMap { line -> String? in
            let fields = line.split(whereSeparator: \.isWhitespace)
            guard fields.count >= 4,
                  ["default", "0/1", "128.0/1", "0.0.0.0/1", "128.0.0.0/1"].contains(String(fields[0])),
                  fields[3].range(of: #"\A[a-zA-Z0-9]{1,15}\z"#, options: .regularExpression) != nil else {
                return nil
            }
            return "\(fields[0]) → \(fields[3])"
        }
        return routes.isEmpty ? "未找到默认路由或全局分段路由" : routes.joined(separator: "，")
    }

    private static func command(_ executable: String, _ arguments: [String]) -> (code: Int32, output: String) {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = arguments
        process.environment = ["PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL": "C"]
        process.standardInput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        let pipe = Pipe()
        process.standardOutput = pipe
        do { try process.run() } catch { return (-1, "") }
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        return (process.terminationStatus, String(decoding: data, as: UTF8.self))
    }
}
