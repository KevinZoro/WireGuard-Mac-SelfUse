import AppKit
import SwiftUI

@MainActor
final class TunnelModel: ObservableObject {
    struct Pending {
        let operation: Operation
        let config: TunnelConfig
    }

    @Published private(set) var configURL = FileManager.default.homeDirectoryForCurrentUser
        .appendingPathComponent("Downloads/mac.conf")
    @Published var line = ConnectionLine(rawValue: UserDefaults.standard.string(forKey: "connectionLine") ?? "")
        ?? .wireGuard {
        didSet {
            UserDefaults.standard.set(line.rawValue, forKey: "connectionLine")
            if oldValue != line { message = nil }
        }
    }
    @Published var mode = ConnectionPreferences().mode {
        didSet {
            ConnectionPreferences().mode = mode
            if oldValue != mode { message = nil }
        }
    }
    @Published var directApps = ConnectionPreferences().directApps {
        didSet { ConnectionPreferences().directApps = directApps }
    }
    @Published private(set) var realityURL = UserDefaults.standard.string(forKey: "realityProfilePath")
        .map { URL(fileURLWithPath: $0) } ?? ConnectionProfile.defaultRealityURL
    @Published private(set) var state: TunnelState = .unknown
    @Published private(set) var checkedAt: Date?
    @Published private(set) var busy: String?
    @Published private(set) var message: String?
    @Published private(set) var pending: Pending?
    @Published private(set) var autoRefreshPaused = false
    @Published private(set) var diagnosis: NetworkDiagnosis?
    @Published private(set) var diagnosing = false
    private var observedReference: TunnelReference?
    private var refreshGeneration = UUID()

    var locked: Bool { busy != nil || pending != nil || diagnosing }

    var wireGuardActive: Bool {
        if case .active = state { return true }
        return false
    }

    private var requestedStart: ConnectionStart { mode.start(on: line, directApps: directApps) }

    var profile: ConnectionProfile {
        ConnectionProfile(line: line, url: line == .wireGuard ? configURL : realityURL)
    }

    func canChangeConnection(website: WebsiteSplitModel, tun: AppSplitModel) -> Bool {
        !locked && !website.inUse && !tun.inUse && !wireGuardActive
    }

    func connectTitle(tun: AppSplitModel) -> String {
        if needsSingBox(tun: tun) { return "安装 sing-box" }
        return mode == .appSplit ? "连接 App 分流" : "连接全局 IPv4"
    }

    func needsSingBox(tun: AppSplitModel) -> Bool {
        requestedStart != .wireGuard && !tun.installed
    }

    func canPerform(_ action: Operation, website: WebsiteSplitModel, tun: AppSplitModel) -> Bool {
        guard !locked else { return false }
        switch action {
        case .up:
            guard canChangeConnection(website: website, tun: tun) else { return false }
            if requestedStart == .wireGuard { return canConnect }
            return mode == .global || !directApps.isEmpty
        case .down:
            if tun.inUse { return tun.running && tun.busy == nil }
            return line == .wireGuard && canDisconnect
        case .status:
            if tun.inUse { return tun.running && tun.busy == nil && !tun.checkingExit }
            return line == .wireGuard
        }
    }

    func perform(_ action: Operation, website: WebsiteSplitModel, tun: AppSplitModel) {
        guard canPerform(action, website: website, tun: tun) else { return }
        switch action {
        case .up:
            ConnectionPreferences().mode = mode
            switch requestedStart {
            case .wireGuard:
                start(action)
            case .singBox(let paths):
                message = nil
                if tun.installed {
                    tun.start(profile: profile, directApps: paths)
                } else {
                    tun.install(for: profile, mode: mode)
                }
            }
        case .down where tun.running:
            tun.stop()
        case .status where tun.running:
            tun.checkExit()
        case .down, .status:
            start(action)
        }
    }

    var canConnect: Bool { !locked && (state == .unknown || state == .inactive) }

    var canDisconnect: Bool {
        guard !locked else { return false }
        return switch state {
        case .unknown, .active: true
        case .inactive, .conflict: false
        }
    }

    func choose() {
        guard !locked else { return }
        refreshGeneration = UUID()
        let selectedLine = line
        let panel = NSOpenPanel()
        panel.title = "选择\(selectedLine.title)配置"
        panel.message = selectedLine == .wireGuard
            ? "请选择本机可信的 .conf 配置文件。"
            : "请选择部署时生成的 sing-box 客户端配置。"
        panel.prompt = "选择配置"
        panel.directoryURL = profile.url.deletingLastPathComponent()
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = false
        busy = "正在选择配置…"
        panel.begin { [weak self] result in
            guard let self else { return }
            defer { self.busy = nil }
            guard result == .OK, let url = panel.url else { return }
            if selectedLine == .reality {
                do {
                    _ = try RealityProfile.outbound(at: url)
                    self.realityURL = url
                    UserDefaults.standard.set(url.path, forKey: "realityProfilePath")
                    self.message = nil
                } catch let error as UserError {
                    self.message = error.message
                } catch {
                    self.message = "无法读取 REALITY 配置。"
                }
                return
            }
            guard url.pathExtension.lowercased() == "conf" else {
                self.message = "请选择一个 .conf 配置文件。"
                return
            }
            self.configURL = url
            self.checkedAt = nil
            self.state = .unknown
            self.message = nil
            self.observedReference = nil
            self.autoRefreshPaused = false
        }
    }

    func start(_ operation: Operation) {
        guard !locked else { return }
        refreshGeneration = UUID()
        busy = wireGuardProgress(operation)
        message = nil
        let url = configURL
        Task {
            do {
                let config = try await Task.detached(priority: .userInitiated) {
                    try TunnelConfig.load(url)
                }.value
                if operation == .status {
                    await execute(operation, config: config)
                } else {
                    if let error = config.mutationError { throw error }
                    pending = Pending(operation: operation, config: config)
                    busy = nil
                }
            } catch {
                finishWithError(error)
            }
        }
    }

    func cancel() {
        if let pending { message = "已取消\(pending.operation.title)。" }
        pending = nil
    }

    func diagnose() {
        guard !locked else { return }
        diagnosing = true
        diagnosis = nil
        let reference = observedReference
        Task {
            diagnosis = await Task.detached(priority: .utility) {
                await NetworkDiagnosis.collect(reference: reference)
            }.value
            diagnosing = false
        }
    }

    func confirm() {
        guard let pending, busy == nil else { return }
        busy = wireGuardProgress(pending.operation)
        self.pending = nil
        Task { await execute(pending.operation, config: pending.config) }
    }

    func refreshWhileOpen() async {
        while !Task.isCancelled {
            await observe()
            do {
                try await Task.sleep(for: .seconds(5))
            } catch {
                return
            }
        }
    }

    private func observe() async {
        guard !locked, !autoRefreshPaused, case .active = state, let observedReference else { return }
        let generation = refreshGeneration
        let observation = await Task.detached(priority: .utility) {
            TunnelClient.observe(observedReference)
        }.value
        guard !Task.isCancelled, generation == refreshGeneration, !locked else { return }
        switch observation {
        case .snapshot(let snapshot):
            state = snapshot
            checkedAt = Date()
        case .paused:
            autoRefreshPaused = true
        case .skipped:
            break
        }
    }

    private func execute(_ operation: Operation, config: TunnelConfig) async {
        busy = wireGuardProgress(operation)
        defer { busy = nil }
        do {
            let reply = try await Task.detached(priority: .userInitiated) {
                try TunnelClient.perform(operation, config: config)
            }.value
            message = reply.message
            if !reply.cancelled {
                state = reply.state
                checkedAt = reply.state == .unknown ? nil : Date()
                observedReference = config.reference
                autoRefreshPaused = false
            }
        } catch {
            finishWithError(error)
        }
    }

    private func wireGuardProgress(_ operation: Operation) -> String {
        switch operation {
        case .up: "正在连接 · \(ConnectionMode.global.title)"
        case .down: "正在断开 · \(ConnectionMode.global.title)"
        case .status: operation.progress
        }
    }

    private func finishWithError(_ error: Error) {
        message = (error as? UserError)?.message ?? "无法完成本机操作。"
        state = .unknown
        checkedAt = nil
        observedReference = nil
        autoRefreshPaused = false
        busy = nil
    }
}

struct TunnelView: View {
    @ObservedObject var model: TunnelModel
    @ObservedObject var split: WebsiteSplitModel
    @ObservedObject var appSplit: AppSplitModel
    @State private var showingWebsiteSplit = false
    @State private var showingAppSplit = false
    @State private var tunTraffic: TunnelTraffic?

    private var connected: Bool { model.wireGuardActive || appSplit.running }
    private var canChangeConnection: Bool { model.canChangeConnection(website: split, tun: appSplit) }

    var body: some View {
        VStack(alignment: .leading, spacing: 20) {
            HStack {
                Text("WireGuard 控制台")
                    .font(.system(size: 25, weight: .semibold))
                Spacer()
                Button { perform(.status) } label: {
                    Label("刷新状态", systemImage: "arrow.clockwise")
                        .labelStyle(.iconOnly)
                }
                .help("刷新状态")
                .disabled(!canPerform(.status))
            }

            VStack(alignment: .leading, spacing: 10) {
                Picker("线路", selection: $model.line) {
                    Text("WireGuard · UDP").tag(ConnectionLine.wireGuard)
                    Text("VLESS + REALITY · TCP").tag(ConnectionLine.reality)
                }
                .pickerStyle(.segmented)
                .disabled(!canChangeConnection)

                Picker("模式", selection: $model.mode) {
                    ForEach(ConnectionMode.allCases, id: \.self) { mode in
                        Text(mode.title).tag(mode)
                    }
                }
                .pickerStyle(.segmented)
                .disabled(!canChangeConnection)

                if model.mode == .appSplit {
                    HStack {
                        Text(model.directApps.isEmpty ? "添加至少一个要直连的 App。" : "直连名单已添加 \(model.directApps.count) 个 App。")
                            .font(.callout)
                            .foregroundStyle(.secondary)
                        Spacer()
                        Button(canChangeConnection ? "编辑名单…" : "查看名单…") {
                            showingAppSplit = true
                        }
                        .accessibilityLabel(canChangeConnection ? "编辑直连 App 名单" : "查看直连 App 名单")
                    }
                    if model.directApps.contains(where: AppSplitView.isSafari) {
                        Label("Safari 网页流量仍走隧道，详见直连名单。",
                              systemImage: "exclamationmark.triangle")
                            .font(.callout)
                            .foregroundStyle(.secondary)
                    }
                }
                if connected || split.inUse {
                    Text(split.inUse ? "停止网站分流后可切换线路或模式。" : "断开后可切换线路或模式。")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                } else if model.needsSingBox(tun: appSplit) && !appSplit.inUse {
                    Text("\(model.mode.title)需要安装 sing-box。")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                }
            }

            VStack(alignment: .leading, spacing: 13) {
                if model.wireGuardActive || (model.line == .wireGuard && model.mode == .global && !appSplit.inUse) {
                    TimelineView(.periodic(from: .now, by: 5)) { timeline in
                        statusPanel(now: timeline.date)
                    }
                } else {
                    tunStatus
                }
                if let message = model.message ?? appSplit.message(for: model.profile, mode: model.mode) {
                    Label(message, systemImage: "info.circle")
                        .font(.callout)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(16)
            .background(.quaternary.opacity(0.5), in: RoundedRectangle(cornerRadius: 12))

            HStack(alignment: .center, spacing: 12) {
                VStack(alignment: .leading, spacing: 4) {
                    Text("配置文件").font(.subheadline.weight(.semibold))
                    Text(model.profile.url.path)
                        .font(.callout)
                        .foregroundStyle(.secondary)
                        .lineLimit(2)
                        .truncationMode(.middle)
                        .help(model.profile.url.path)
                }
                Spacer(minLength: 8)
                Button("选择配置…", action: model.choose)
                    .disabled(!canChangeConnection)
            }

            HStack(spacing: 10) {
                if connected {
                    Button("断开") { perform(.down) }
                        .buttonStyle(.borderedProminent)
                        .disabled(!canPerform(.down))
                } else {
                    Button(model.connectTitle(tun: appSplit)) { perform(.up) }
                        .buttonStyle(.borderedProminent)
                        .keyboardShortcut(.defaultAction)
                        .disabled(!canPerform(.up))
                }
                Button(split.running ? "网站分流（运行中）" : "网站分流…") {
                    showingWebsiteSplit = true
                }
                .disabled(model.locked || appSplit.inUse)
                if model.line == .wireGuard && model.mode == .global {
                    Button(model.diagnosing ? "检测中…" : "检测网络", action: model.diagnose)
                        .disabled(model.locked || split.inUse || appSplit.inUse)
                }
                Spacer()
            }

            if model.line == .wireGuard, let diagnosis = model.diagnosis {
                HStack(alignment: .top) {
                    Text(diagnosis.summary)
                        .font(.callout)
                        .fixedSize(horizontal: false, vertical: true)
                    Spacer()
                    Button("复制诊断") {
                        NSPasteboard.general.clearContents()
                        NSPasteboard.general.setString(diagnosis.report, forType: .string)
                    }
                }
            }

            Divider()
            Label(model.line == .wireGuard ? "默认 mac.conf 仅接管 IPv4，IPv6 不受该配置保护。"
                  : "此线路接管 IPv4 流量。IPv6 沿用系统路由。", systemImage: "info.circle")
                .font(.callout)
                .foregroundStyle(.secondary)
        }
        .padding(26)
        .frame(minWidth: 560, maxWidth: 720)
        .task {
            appSplit.refreshDependency()
            await model.refreshWhileOpen()
        }
        .task(id: appSplit.running) {
            tunTraffic = nil
            if appSplit.running { await refreshTraffic() }
        }
        .onChange(of: model.directApps) { _ in appSplit.clearMessage() }
        .onChange(of: model.profile) { _ in appSplit.clearMessage() }
        .sheet(isPresented: $showingAppSplit) {
            AppSplitView(apps: $model.directApps, editable: canChangeConnection)
        }
        .sheet(isPresented: $showingWebsiteSplit) {
            WebsiteSplitView(split: split, tunnel: model)
        }
        .sheet(isPresented: Binding(
            get: { model.pending != nil },
            set: { if !$0 { model.cancel() } }
        )) {
            if let pending = model.pending {
                VStack(alignment: .leading, spacing: 14) {
                    Text("授权\(pending.operation.title)").font(.title2.weight(.semibold))
                    Text("确认这是你信任的配置。首次操作或授权会话过期时，macOS 会请求管理员授权。")
                    Text(pending.config.url.path)
                        .font(.callout.monospaced())
                        .foregroundStyle(.secondary)
                        .textSelection(.enabled)
                    HStack {
                        Spacer()
                        Button("取消", action: model.cancel).keyboardShortcut(.cancelAction)
                        Button("授权并\(pending.operation.title)", action: model.confirm)
                            .buttonStyle(.borderedProminent)
                    }
                }
                .padding(24)
                .frame(width: 450)
            }
        }
    }

    private func canPerform(_ operation: Operation) -> Bool {
        model.canPerform(operation, website: split, tun: appSplit)
    }

    private func perform(_ operation: Operation) {
        model.perform(operation, website: split, tun: appSplit)
    }

    private var tunStatus: some View {
        VStack(alignment: .leading, spacing: 13) {
            if let busy = appSplit.busy ?? model.busy {
                progress(busy)
            } else if !appSplit.running {
                Label("未连接 · \(model.mode.title)", systemImage: "circle")
                    .font(.title3.weight(.semibold))
                    .foregroundStyle(.secondary)
            } else {
                Label {
                    Text("已连接 · \(appSplit.mode.title)")
                } icon: {
                    Image(systemName: "checkmark.circle.fill").foregroundStyle(.green)
                }
                .font(.title3.weight(.semibold))
                Text(model.line.title)
                    .font(.callout)
                    .foregroundStyle(.secondary)
                tunDiagnostics
            }
            if appSplit.running {
                HStack(spacing: 14) {
                    statistic("虚拟网卡接收", tunTraffic.map { Self.byteCount($0.received) } ?? "—")
                    statistic("虚拟网卡发送", tunTraffic.map { Self.byteCount($0.sent) } ?? "—")
                }
            }
        }
    }

    private var tunDiagnostics: some View {
        Group {
            HStack(spacing: 14) {
                if appSplit.checkingExit {
                    Text("正在检测隧道出口与 OpenAI HTTPS…")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                } else if let checkedAt = appSplit.exitCheckedAt {
                    statistic("隧道出口 IPv4", appSplit.exitIP ?? "探测失败")
                    statistic("OpenAI HTTPS", appSplit.httpsAvailable ? "可达" : "探测失败")
                    statistic("检测时间", checkedAt.formatted(date: .omitted, time: .standard))
                }
            }
            if appSplit.exitCheckedAt != nil, !appSplit.checkingExit,
               appSplit.exitIP == nil || !appSplit.httpsAvailable {
                Button("重新检测") { perform(.status) }
                    .disabled(!canPerform(.status))
            }
        }
    }

    private func progress(_ text: String) -> some View {
        HStack {
            ProgressView().controlSize(.small).accessibilityHidden(true)
            Text(text)
        }
        .font(.title3.weight(.semibold))
    }

    private func refreshTraffic() async {
        while !Task.isCancelled {
            let sample = await Task.detached(priority: .utility) {
                TunnelTraffic.read(tunIPv4Address: WebsiteProxyConfig.tunIPv4Address)
            }.value
            guard !Task.isCancelled else { return }
            tunTraffic = sample
            do {
                try await Task.sleep(for: .seconds(2))
            } catch {
                return
            }
        }
    }

    private func statusPanel(now: Date) -> some View {
        let (title, icon, color, metrics) = status(at: now)
        return VStack(alignment: .leading, spacing: 13) {
            if let busy = model.busy {
                progress(busy)
            } else if let pending = model.pending {
                Label("等待\(pending.operation.title)授权 · 全局 IPv4", systemImage: "lock")
                    .font(.title3.weight(.semibold))
            } else {
                HStack {
                    Label {
                        Text(title)
                    } icon: {
                        Image(systemName: icon).foregroundStyle(color)
                    }
                    .font(.title3.weight(.semibold))
                    Spacer()
                    if let checkedAt = model.checkedAt {
                        Text("刷新于 \(checkedAt.formatted(date: .omitted, time: .standard))")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
            }
            if let metrics {
                Text("WireGuard")
                    .font(.callout)
                    .foregroundStyle(.secondary)
                HStack(alignment: .top, spacing: 14) {
                    statistic("最近握手", metrics.handshake?.formatted(date: .abbreviated, time: .standard) ?? "尚无")
                    statistic("接收", Self.byteCount(metrics.received))
                    statistic("发送", Self.byteCount(metrics.sent))
                }
                if model.autoRefreshPaused {
                    Text("自动刷新暂停，可点右上角刷新状态。")
                        .font(.callout).foregroundStyle(.secondary)
                } else if metrics.peers == 0 || metrics.handshake == nil {
                    Text(metrics.peers == 0 ? "当前没有对端。" : "等待首次握手。")
                        .font(.callout).foregroundStyle(.secondary)
                }
            }
        }
    }

    private func status(at now: Date) -> (String, String, Color, Metrics?) {
        switch model.state {
        case .unknown:
            return ("状态未知", "questionmark.circle", .secondary, nil)
        case .inactive:
            return ("未连接", "circle", .secondary, nil)
        case .conflict:
            return ("同名隧道与配置不匹配", "exclamationmark.triangle", .orange, nil)
        case .active(let metrics):
            let verified = !model.autoRefreshPaused && metrics.hasRecentHandshake(at: now)
            return ("已连接 · 全局 IPv4", verified ? "checkmark.circle.fill" : "clock",
                    verified ? .green : .secondary, metrics)
        }
    }

    private func statistic(_ title: String, _ value: String) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(title).font(.caption).foregroundStyle(.secondary)
            Text(value).font(.callout.monospacedDigit())
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .accessibilityElement(children: .combine)
    }

    private static func byteCount(_ count: UInt64) -> String {
        ByteCountFormatter.string(fromByteCount: Int64(clamping: count), countStyle: .binary)
    }
}

struct TunnelMenu: View {
    @Environment(\.openWindow) private var openWindow
    @ObservedObject var model: TunnelModel
    @ObservedObject var split: WebsiteSplitModel
    @ObservedObject var appSplit: AppSplitModel

    var body: some View {
        Button("打开控制台", action: showConsole)
        Picker("线路", selection: $model.line) {
            ForEach(ConnectionLine.allCases, id: \.self) { line in
                Text(line.title).tag(line)
            }
        }
        .disabled(!model.canChangeConnection(website: split, tun: appSplit))
        Picker("模式", selection: $model.mode) {
            ForEach(ConnectionMode.allCases, id: \.self) { mode in
                Text(mode.title).tag(mode)
            }
        }
        .disabled(!model.canChangeConnection(website: split, tun: appSplit))
        Divider()
        if let busy = appSplit.busy ?? model.busy {
            Text(busy)
        } else if appSplit.running || model.wireGuardActive {
            Text("已连接 · \((appSplit.running ? appSplit.mode : .global).title)")
        } else {
            Button(model.connectTitle(tun: appSplit)) { start(.up) }
                .disabled(!model.canPerform(.up, website: split, tun: appSplit))
        }
        Button("断开") { start(.down) }
            .disabled(!model.canPerform(.down, website: split, tun: appSplit))
        Button("刷新状态") { start(.status) }
            .disabled(!model.canPerform(.status, website: split, tun: appSplit))
        Divider()
        Button("退出 WireGuard 控制台") { NSApp.terminate(nil) }
            .disabled(model.locked || appSplit.busy != nil)
    }

    private func showConsole() {
        openWindow(id: "main")
        if #available(macOS 14, *) {
            NSApp.activate()
        } else {
            NSApp.activate(ignoringOtherApps: true)
        }
    }

    private func start(_ operation: Operation) {
        showConsole()
        model.perform(operation, website: split, tun: appSplit)
    }
}

private enum TunnelMenuIcon {
    static let image: NSImage = {
        let icon = NSImage(size: NSSize(width: 20, height: 16), flipped: false) { _ in
            let paths = NSBezierPath()
            paths.lineWidth = 1.7
            paths.lineCapStyle = .round
            paths.move(to: NSPoint(x: 1.5, y: 7.0))
            paths.line(to: NSPoint(x: 4.0, y: 7.0))
            paths.curve(to: NSPoint(x: 6.8, y: 9.8),
                        controlPoint1: NSPoint(x: 5.6, y: 7.0),
                        controlPoint2: NSPoint(x: 6.6, y: 7.9))
            paths.curve(to: NSPoint(x: 18.5, y: 9.8),
                        controlPoint1: NSPoint(x: 7.8, y: 16.1),
                        controlPoint2: NSPoint(x: 18.5, y: 16.1))
            paths.line(to: NSPoint(x: 18.5, y: 4.5))

            paths.move(to: NSPoint(x: 1.5, y: 3.7))
            paths.line(to: NSPoint(x: 5.0, y: 3.7))
            paths.curve(to: NSPoint(x: 9.8, y: 8.6),
                        controlPoint1: NSPoint(x: 8.1, y: 3.7),
                        controlPoint2: NSPoint(x: 9.5, y: 6.1))
            paths.curve(to: NSPoint(x: 15.2, y: 8.6),
                        controlPoint1: NSPoint(x: 10.1, y: 11.7),
                        controlPoint2: NSPoint(x: 15.2, y: 11.7))
            paths.line(to: NSPoint(x: 15.2, y: 1.9))

            NSColor.black.setStroke()
            paths.stroke()
            return true
        }
        icon.isTemplate = true
        return icon
    }()
}

@main
struct WireGuardControlApp: App {
    @StateObject private var model = TunnelModel()
    @StateObject private var split = WebsiteSplitModel()
    @StateObject private var appSplit = AppSplitModel()

    var body: some Scene {
        Window("WireGuard 控制台", id: "main") {
            TunnelView(model: model, split: split, appSplit: appSplit)
        }
        .windowResizability(.contentSize)

        MenuBarExtra {
            TunnelMenu(model: model, split: split, appSplit: appSplit)
        } label: {
            Image(nsImage: TunnelMenuIcon.image)
                .accessibilityLabel("WireGuard 控制台")
        }
        .menuBarExtraStyle(.menu)
    }
}
