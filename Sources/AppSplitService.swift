import Foundation

enum AppSplitService {
    static let executable = "/opt/homebrew/bin/sing-box"

    static var installed: Bool {
        FileManager.default.isExecutableFile(atPath: executable)
    }

    static func install() throws {
        let brew = "/opt/homebrew/bin/brew"
        guard FileManager.default.isExecutableFile(atPath: brew) else {
            throw UserError("未找到 ARM Homebrew。安装 Homebrew 后再试。")
        }
        let child = Process()
        child.executableURL = URL(fileURLWithPath: brew)
        child.arguments = ["install", "sing-box"]
        var environment = ProcessInfo.processInfo.environment
        environment["PATH"] = "/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin"
        environment["HOMEBREW_NO_AUTO_UPDATE"] = "1"
        environment["HOMEBREW_NO_INSTALL_UPGRADE"] = "1"
        environment["HOMEBREW_NO_INSTALL_CLEANUP"] = "1"
        environment["HOMEBREW_NO_ANALYTICS"] = "1"
        environment["HOMEBREW_NO_ASK"] = "1"
        child.environment = environment
        child.standardInput = FileHandle.nullDevice
        child.standardOutput = FileHandle.nullDevice
        child.standardError = FileHandle.nullDevice
        try child.run()
        child.waitUntilExit()
        guard child.terminationStatus == 0, installed else {
            throw UserError("Homebrew 安装未完成。请检查网络后重试。")
        }
    }

    static func start(profile: ConnectionProfile, directApps: [URL]?) throws -> AuthorizationSession {
        guard installed else { throw UserError("请先安装 sing-box。") }
        try WebsiteProxyService.checkSystemRoutes()
        let json: Data
        if let directApps {
            json = try WebsiteProxyConfig.makeAppSplit(from: profile, directApps: directApps)
        } else {
            json = try WebsiteProxyConfig.makeGlobalReality(from: profile.url)
        }
        let tools = try SessionToolkit.prepareAppSplit(executable: executable, configuration: json)
        switch try AuthorizationSession.startAppSplit(tools: tools) {
        case .connected(let session):
            return session
        case .rejected(let reply):
            switch reply.trimmingCharacters(in: .whitespacesAndNewlines) {
            case "CANCELLED": throw UserError("已取消系统授权。")
            case "AUTH_FAILED": throw UserError("系统授权失败。")
            case "BUSY", "VPN_ACTIVE": throw UserError("请先断开已启动的 VPN。")
            case "TUN_ADDRESS_IN_USE": throw UserError("分流虚拟网卡的地址已被占用。")
            case "TUN_DNS_FAILED": throw UserError("macOS 未采用隧道的 DNS。REALITY 已停止，请重试。")
            default: throw UserError("未能启动虚拟网卡。请检查线路配置和 sing-box 版本。")
            }
        }
    }
}
