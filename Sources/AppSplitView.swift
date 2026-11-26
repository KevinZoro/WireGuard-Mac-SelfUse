import AppKit
import SwiftUI

@MainActor
final class AppSplitModel: ObservableObject {
    @Published private(set) var installed = AppSplitService.installed
    @Published private(set) var busy: String?
    @Published private(set) var running = false
    @Published private var message: String?
    @Published private(set) var mode: ConnectionMode = .global
    @Published private(set) var exitIP: String?
    @Published private(set) var httpsAvailable = false
    @Published private(set) var exitCheckedAt: Date?
    @Published private(set) var checkingExit = false
    private var session: AuthorizationSession?
    private var lastProfile: ConnectionProfile?

    var inUse: Bool { running || busy != nil }

    func message(for profile: ConnectionProfile, mode: ConnectionMode) -> String? {
        lastProfile == profile && self.mode == mode ? message : nil
    }

    func clearMessage() {
        message = nil
    }

    func refreshDependency() {
        installed = AppSplitService.installed
    }

    func install(for profile: ConnectionProfile, mode: ConnectionMode) {
        guard !inUse else { return }
        lastProfile = profile
        self.mode = mode
        busy = "正在安装 sing-box…"
        message = nil
        Task {
            defer {
                refreshDependency()
                busy = nil
            }
            do {
                try await Task.detached(priority: .userInitiated) {
                    try AppSplitService.install()
                }.value
            } catch {
                message = (error as? UserError)?.message ?? "无法运行 Homebrew 安装。"
            }
        }
    }

    func start(profile: ConnectionProfile, directApps: [URL]? = nil) {
        guard !inUse else { return }
        lastProfile = profile
        mode = directApps == nil ? .global : .appSplit
        exitIP = nil
        httpsAvailable = false
        exitCheckedAt = nil
        busy = "正在连接 · \(mode.title)"
        message = nil
        Task {
            do {
                let connection = try await Task.detached(priority: .userInitiated) {
                    try AppSplitService.start(profile: profile, directApps: directApps)
                }.value
                session = connection
                running = true
                busy = nil
                let child = connection.process
                child.terminationHandler = { [weak self] ended in
                    Task { @MainActor in self?.didStop(ended) }
                }
                if !child.isRunning { didStop(child) }
                checkExit()
            } catch {
                refreshDependency()
                message = (error as? UserError)?.message ?? "无法启动所选线路。"
                busy = nil
            }
        }
    }

    func stop() {
        guard running, busy == nil else { return }
        busy = "正在断开 · \(mode.title)"
        session?.stopAppSplit()
    }

    func checkExit() {
        guard running, busy == nil, !checkingExit, let connection = session else { return }
        checkingExit = true
        Task {
            async let address = Task.detached(priority: .utility) {
                NetworkDiagnosis.publicIPv4()
            }.value
            async let https = Task.detached(priority: .utility) {
                NetworkDiagnosis.openAIHTTPSThroughTUN()
            }.value
            let (exit, reachable) = await (address, https)
            guard session === connection else { return }
            exitIP = exit
            httpsAvailable = reachable
            exitCheckedAt = Date()
            checkingExit = false
        }
    }

    private func didStop(_ child: Process) {
        guard child === session?.process else { return }
        if busy == nil { message = "\(mode.title)连接已中断，可以重新连接。" }
        session = nil
        running = false
        exitIP = nil
        httpsAvailable = false
        exitCheckedAt = nil
        checkingExit = false
        busy = nil
    }
}

struct AppSplitView: View {
    @Binding var apps: [URL]
    let editable: Bool
    @Environment(\.dismiss) private var dismiss

    static func isSafari(_ url: URL) -> Bool {
        Bundle(url: url.resolvingSymlinksInPath())?.bundleIdentifier == "com.apple.Safari"
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("直连 App 名单").font(.title2.weight(.semibold))
            Text("分流按 App 的安装路径匹配进程，匹配到的连接会直连。")
                .foregroundStyle(.secondary)
            if !editable {
                Text("断开连接后可编辑名单。").foregroundStyle(.secondary)
            }
            if apps.isEmpty {
                Text("还没有添加直连例外。").foregroundStyle(.secondary)
            } else {
                ScrollView {
                    VStack(alignment: .leading) {
                        ForEach(apps, id: \.self) { app in
                            HStack {
                                VStack(alignment: .leading) {
                                    Text(app.deletingPathExtension().lastPathComponent)
                                    Text(app.path).font(.caption).foregroundStyle(.secondary)
                                    if Self.isSafari(app) {
                                        Label("Safari 的网页请求由系统 WebKit 发出，仍走隧道。",
                                              systemImage: "exclamationmark.triangle")
                                            .font(.callout)
                                            .fixedSize(horizontal: false, vertical: true)
                                    }
                                }
                                Spacer()
                                Button("移除") {
                                    apps.removeAll { $0 == app }
                                }
                                .accessibilityLabel("移除 \(app.deletingPathExtension().lastPathComponent)")
                                .disabled(!editable)
                            }
                        }
                    }
                }
                .frame(maxHeight: 160)
            }
            Button("添加直连 App…", action: chooseApps)
                .disabled(!editable)
            HStack {
                Spacer()
                Button("完成") { dismiss() }.keyboardShortcut(.defaultAction)
            }
        }
        .padding(24)
        .frame(width: 510)
        .onExitCommand { dismiss() }
    }

    private func chooseApps() {
        let panel = NSOpenPanel()
        panel.allowedContentTypes = [.applicationBundle]
        panel.allowsMultipleSelection = true
        panel.directoryURL = URL(fileURLWithPath: "/Applications", isDirectory: true)
        if panel.runModal() == .OK {
            apps = Array(Set(apps + panel.urls)).sorted { $0.path < $1.path }
        }
    }
}
