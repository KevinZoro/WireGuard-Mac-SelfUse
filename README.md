# WireGuard Control · macOS

为自建服务器准备的 macOS 菜单栏客户端。支持 **WireGuard（UDP）** 和 **VLESS + REALITY（TCP）**，可在主窗口或菜单栏选择线路和连接模式，查看连接状态、出口与流量。

## 功能

| 模式 | 生效范围 | 运行依赖 |
| --- | --- | --- |
| WireGuard 全局 | 由 WireGuard 配置的 `AllowedIPs` 决定 | `wireguard-tools` |
| REALITY 全局 IPv4 | 系统 IPv4 流量 | `sing-box` |
| App 分流 | 名单里命中的 App 进程直连，其余由虚拟网卡接管的 IPv4 流量走所选线路 | `sing-box` |
| 网站分流 | 分流版 Chrome 窗口。指定域名及其子域名直连，其余走所选线路 | `sing-box`、Google Chrome |

全局 WireGuard 连接可查看最近握手与累计收发量。REALITY 和 App 分流可查看隧道出口 IPv4、HTTPS 探测结果与虚拟网卡累计流量。模式和 App 直连名单会保存在本机。

## 安装与启动

需要 **Apple Silicon Mac（arm64）和 macOS 13 或更新版本**。从源码构建需要 Xcode 或 Command Line Tools，运行时按所用模式安装 ARM 版 [Homebrew](https://brew.sh/) 依赖。

```bash
xcode-select --install     # 尚未安装开发工具时执行
brew install wireguard-tools
brew install sing-box
./build.sh
```

在仓库根目录运行构建命令后，从 Finder 打开 `build/WireGuard Control.app`。构建也会生成 `build/WireGuard-Control-arm64.zip`。构建产物采用 ad hoc 签名，未做 Apple 公证。首次打开时 macOS 可能要求确认。 [Apple 打开 App 指南](https://support.apple.com/102445)

## 首次连接

1. 准备自己的客户端配置。**WireGuard** 使用 `wg-quick` 格式的 `.conf`。**REALITY** 使用 sing-box JSON 客户端配置，内含一个 VLESS + REALITY 出站。支持直连 TCP，`flow` 可留空或使用 `xtls-rprx-vision`。
2. 打开控制台，在「线路」里选择协议，再用「选择配置…」导入文件。
3. 选择「全局 IPv4」或「App 分流」。如选 App 分流，先点「编辑名单…」，至少加入一个需要直连的 App。
4. 点连接按钮，按 macOS 提示授权。状态卡会显示当前模式。可用自己信任的 IPv4 查询服务核对出口，断开后可切换线路或模式。

两种协议都需要自己的服务端和匹配的凭据，仓库和构建产物均不附带节点。

## 使用限制

- REALITY 和 App 分流的虚拟网卡接管 IPv4。IPv6 沿用系统路由。WireGuard 全局模式以导入的配置为准。
- App 分流按应用包路径匹配实际发起连接的进程。Safari 的网页请求由应用包之外的系统 WebKit 进程发出，即使 Safari 在直连名单里，网页请求仍走隧道。
- 基于 sing-box 的 WireGuard 分流要求配置包含一个 Peer 和 IPv4 隧道地址，且 `AllowedIPs` 包含 `0.0.0.0/0`。
- 关闭主窗口后连接仍可运行。退出客户端会结束由 sing-box 启动的会话。全局 WireGuard 隧道可在退出后继续运行，需要结束时请在客户端点「断开」。

## 配置与隐私

配置在本机读取。其中的 UUID、私钥和预共享密钥应保留在本机。控制台通过系统授权启动需要特权的操作，使用临时配置并在使用后清理。WireGuard 配置不允许执行 `PreUp`、`PostUp`、`PreDown`、`PostDown`，也不允许启用 `SaveConfig`。

连接后的出口和可达性检测会请求公网服务并显示结果。提交问题时，可描述 macOS 版本、线路与模式、界面状态和复现步骤。分享配置、日志或截图前，请移除公网 IP、服务器地址、密钥、UUID 和本机用户名。

## 开发

```bash
./test.sh
```

自测使用合成配置，覆盖导入校验、分流规则、模式持久化、授权脚本和状态解析，无需管理员权限。应用代码位于 `Sources/`，测试位于 `Tests/`。

连接细节、诊断和授权机制见[使用说明](使用说明.md)。

## 许可证

本项目采用 [MIT 许可证](LICENSE)。运行时安装的 WireGuard、sing-box 和其他外部工具各自适用其许可证。
