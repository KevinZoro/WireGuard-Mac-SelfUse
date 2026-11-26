import AppKit
import SwiftUI

@MainActor
final class WebsiteSplitModel: ObservableObject {
    @Published private(set) var running = false
    @Published private(set) var busy = false
    @Published private(set) var message: String?

    private var proxy: WebsiteProxyProcess?
    private var shutdownObserver: NSObjectProtocol?

    var inUse: Bool { running || busy }

    init() {
        shutdownObserver = NotificationCenter.default.addObserver(
            forName: NSApplication.willTerminateNotification, object: nil, queue: .main
        ) { [weak self] _ in
            MainActor.assumeIsolated {
                self?.proxy?.stop()
            }
        }
    }

    deinit {
        if let shutdownObserver { NotificationCenter.default.removeObserver(shutdownObserver) }
    }

    func start(_ input: String, profile: ConnectionProfile) {
        guard !inUse else { return }
        do {
            let rules = try WebsiteRules(input)
            busy = true
            message = nil
            Task {
                do {
                    let service = try await Task.detached(priority: .userInitiated) {
                        try WebsiteProxyService.start(profile: profile, rules: rules)
                    }.value
                    proxy = service
                    let child = service.process
                    running = true
                    busy = false
                    child.terminationHandler = { [weak self] ended in
                        Task { @MainActor in self?.didStop(ended) }
                    }
                    if !child.isRunning { didStop(child) }
                } catch {
                    message = (error as? UserError)?.message ?? "无法启动网站分流。"
                    busy = false
                }
            }
        } catch {
            message = (error as? UserError)?.message ?? "域名规则无效。"
        }
    }

    func stop() {
        guard running, !busy else { return }
        busy = true
        message = nil
        proxy?.stop()
    }

    func openBrowser() {
        guard running, !busy else { return }
        guard let chrome = NSWorkspace.shared.urlForApplication(withBundleIdentifier: "com.google.Chrome"),
              let support = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first else {
            message = "找不到 Google Chrome。"
            return
        }
        let profile = support.appendingPathComponent("WireGuard Control/Split Chrome", isDirectory: true)
        let options = NSWorkspace.OpenConfiguration()
        options.createsNewApplicationInstance = true
        options.arguments = [
            "--user-data-dir=\(profile.path)",
            "--proxy-server=socks5://127.0.0.1:\(WebsiteRules.port)",
            "--no-first-run"
        ]
        NSWorkspace.shared.openApplication(at: chrome, configuration: options) { [weak self] _, error in
            guard error != nil else { return }
            Task { @MainActor in self?.message = "无法打开分流版 Chrome。" }
        }
    }

    private func didStop(_ ended: Process) {
        guard ended === proxy?.process else { return }
        if !busy { message = "本地分流已停止。重新启动后，分流窗口可以继续使用。" }
        proxy = nil
        running = false
        busy = false
    }
}

struct WebsiteSplitView: View {
    @ObservedObject var split: WebsiteSplitModel
    @ObservedObject var tunnel: TunnelModel
    @Environment(\.dismiss) private var dismiss
    @AppStorage("directWebsiteDomains") private var domains = ""

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("网站分流").font(.title2.weight(.semibold))
            Text("在分流版 Chrome 中，列表内域名和子域名直连，其余网站通过\(tunnel.line.title)的 IPv4 出口。")
                .foregroundStyle(.secondary)
            Text("直连域名")
                .font(.subheadline.weight(.semibold))
            TextEditor(text: $domains)
                .font(.body.monospaced())
                .frame(minHeight: 118)
                .border(.quaternary)
                .disabled(split.inUse)
                .accessibilityLabel("直连域名")
            Text("每行一个域名，例如 example.com。")
                .font(.callout)
                .foregroundStyle(.secondary)

            if let message = split.message {
                Label(message, systemImage: "info.circle")
                    .font(.callout)
                    .fixedSize(horizontal: false, vertical: true)
            } else if split.running {
                Label("分流已启动，请打开分流版 Chrome。", systemImage: "checkmark.circle")
                    .font(.callout)
            } else if case .active = tunnel.state {
                Text("请先关闭此窗口，在控制台断开全局 VPN。")
                    .font(.callout)
            }

            HStack {
                if split.busy { ProgressView().controlSize(.small) }
                Spacer()
                Button("关闭") { dismiss() }.keyboardShortcut(.cancelAction)
                if split.running {
                    Button("停止分流", action: split.stop).disabled(split.busy)
                    Button("打开分流版 Chrome", action: split.openBrowser)
                        .buttonStyle(.borderedProminent)
                        .disabled(split.busy)
                } else {
                    Button("启动分流") { split.start(domains, profile: tunnel.profile) }
                        .buttonStyle(.borderedProminent)
                        .disabled(split.busy || tunnel.locked || tunnelIsActive)
                }
            }
        }
        .padding(24)
        .frame(width: 495)
    }

    private var tunnelIsActive: Bool {
        if case .active = tunnel.state { return true }
        return false
    }
}
