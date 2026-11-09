# 风险、差异与限制

## 1. 这是 TUN VPN，不是 Wi-Fi 代理

Wi-Fi 代理由系统网络配置向支持系统代理的应用提供代理地址；本应用则通过 `VpnExtensionAbility` 创建 TUN 虚拟网卡，配置 IPv4 默认路由，并在用户态接管 TCP 会话。手机 Wi-Fi 设置里的代理始终为空。

两者不能视为完全等价：

- 原生 Wi-Fi 代理是否生效取决于应用的网络栈和代理配置；TUN 按路由接管，覆盖面不同。
- 本应用必须自己完成 TCP 三次握手、序号/确认、分包、重传、半关闭及 HTTP 请求头转换，不是把 IP 包直接写入 Charles socket。
- Charles 收到的是标准 HTTP 代理 absolute-form 请求，但原始 TCP 时序、源端口、部分 TCP options 和应用感知的网络路径与 Wi-Fi 代理不同。

## 2. 状态栏 VPN 图标

运行期间系统状态栏会常驻 VPN/钥匙图标，这是系统提醒用户流量经过 VPN 的正常行为，不是悬浮窗或模拟状态。只有系统 VPN 会话销毁后才会消失。

## 3. 只支持明文 TCP HTTP/1.x

- 不实现 TLS、HTTPS CONNECT、SSL Proxying、证书安装或证书校验绕过。
- TLS ClientHello 和非 HTTP TCP 流会被拒绝/重置。大量现代 App 只使用 HTTPS，因此**开启本 VPN 后这些 App 的网络可能不可用**，而不是“忽略 HTTPS 但仍正常联网”。
- 不应把本工具用于生产网络或日常上网；建议只在明确需要抓明文 HTTP 时短时开启。
- 支持普通 GET/POST、keep-alive 和基础流水线请求。单个 `Content-Length` 请求体和单个 chunk 当前上限为 256 KiB，大文件上传不在目标范围内。
- 用户态 TCP 为调试优化，不包含完整内核 TCP 的 SACK、时间戳、窗口缩放、SRTT/Karn 拥塞控制。响应缓冲区、乱序缓冲区和并发连接数均有限制，不追求高吞吐。

## 4. UDP、QUIC、IPv6 与 DNS

- TUN 默认路由没有“只按 TCP 接管”的选项，因此其他 UDP 包也会到达 TUN。
- Native 只中继 UDP/53 DNS，以避免域名解析全部中断；其他 UDP（包括 QUIC/HTTP3）被丢弃，并不是物理网络直接放行。浏览器可能回退 TCP，也可能出现延迟或失败。
- 配置禁用 IPv6；依赖 IPv6-only 网络的应用可能失败。
- DNS 只提供基础 UDP 中继，不支持 DNS over TCP、DNS over HTTPS 的专门处理。

## 5. App 行为差异

部分 App 可能主动检测 VPN、读取系统代理配置、绑定物理网卡，或使用 SSL Pinning。即使同样是 Charles，也可能出现以下差异：

- 检测到 VPN 后拒绝运行或改变行为。
- 不使用系统 Wi-Fi 代理的流量在 Wi-Fi 方案中不可见，但在 TUN 中可能出现。
- Pinning 与 HTTPS 均不属于本工具处理范围。
- Charles 的断点或限流长时间挂起时，Native 连接也有空闲超时和资源上限；当前无活动空闲超时为 10 分钟。

## 6. 调试流量与安全

- 默认 IPv4 路由意味着其他应用的明文 HTTP 也可能进入 Charles，不只当前调试 App。需要限制范围时，在 UI 选择一个目标应用，扩展会设置官方 `trustedApplications: [bundleName]`；选择“全部应用”则仍是全局模式。
- HTTP 内容对同一局域网内的 Charles 电脑可见，不要在代理开启时处理真实账号、支付、隐私或生产凭据。
- 只允许可信电脑和必要网段，不要把 Charles 暴露到公网，不要使用不可信代理。
- Native 遇到单流连接失败会提示错误但保持 VPN 运行；这不是全局停止信号。 fatal TUN 错误才会触发停止流程。

## 7. 生命周期

官方文档说明，发起启动的应用进程退出或 VPN 服务进程销毁时，系统会主动停止 VPN。不要在后台强行保活或规避系统生命周期。关闭时必须同时停止 Native 工作线程并调用 `VpnConnection.destroy()`，否则可能残留 fd、socket 或 VPN 状态。
