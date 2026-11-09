# 常见故障排查清单

## A. 构建或安装失败

- [ ] 使用 DevEco Studio 的 HarmonyOS API 26 SDK；本机验证版本为 `26.0.0.105`。
- [ ] `build-profile.json5` 中 compile/target/compatible 都是 `26.0.0`，Native ABI 为 `arm64-v8a`。
- [ ] 不要手工给 SDK 添加私有 API，也不要把旧示例中的 `setUp()` 替换回来。
- [ ] 如果提示 `type: "vpn"` 无法识别，先升级 DevEco/SDK；不要通过关闭校验规避。官方旧文档曾提示旧 SDK 的 modulecheck 枚举问题，本机 API 26 不需要修改 SDK。
- [ ] `No signingConfig found` 表示只生成了未签名 HAP。到 `Project Structure > Signing Configs` 配置自动调试签名后再 Run。
- [ ] 调试 Profile 必须包含当前 bundleName 和设备；更换包名或设备后重新生成签名。

## B. 点击测试或启动提示无法连接 Charles

按顺序检查：

- [ ] Charles 正在运行，HTTP proxy port 是 `8888`。
- [ ] App 填的是电脑的局域网 IPv4，不是 `127.0.0.1`。
- [ ] 手机与电脑在同一局域网，路由器没有 AP/客户端隔离。
- [ ] `Access Control Settings` 已允许手机 IP 或真实局域网网段。
- [ ] 电脑防火墙已放行 Charles 和 TCP `8888`。
- [ ] 其他安全软件没有拦截 Charles 入站连接。
- [ ] 电脑 IP 最近是否变化；必要时更新 App 中的地址。

探测失败会按要求直接终止启动，不会出现 VPN 授权弹窗。这是预期行为。

## C. 没有弹出 VPN 授权，或启动被拒绝

- [ ] 确认 `module.json5` 中存在 `type: "vpn"` 的 `CharlesVpnExtensionAbility`。
- [ ] `Want.bundleName` 与应用 bundleName 一致，`Want.abilityName` 与扩展名一致。
- [ ] 首次授权被拒绝后，重新启动并在系统弹窗中允许；UI 的 API 26 授权结果回调会显示拒绝提示。
- [ ] 官方错误 `2203001` 表示用户类型/系统策略拒绝创建 VPN；受管控用户、部分多用户或设备管理环境可能不支持。
- [ ] 官方错误 `2203002` 表示已有 VPN。关闭其他 VPN/抓包/加速器应用后重试，必要时在系统 VPN 设置中断开残留连接。
- [ ] 不要申请系统级 `MANAGE_VPN` 试图绕过用户授权；三方扩展的系统信任弹窗仍是必需流程。

## D. 显示运行中，但 Charles 没有请求

- [ ] 测试地址必须是明确的 `http://`，不是 `https://`。
- [ ] 如果选择了单个目标应用，确认它的 Bundle 正确，且请求确实由该应用发出；其他应用按设计不会进入此 VPN。内置项为快手 `com.kuaishou.hmapp`、快手极速版 `com.kuaishou.hmnebula`。
- [ ] 被测 App 是否使用了 QUIC、HTTP/2 over TLS、自定义协议或绑定物理网卡；这些不在支持范围内。
- [ ] Charles 是否按进程/地址过滤了会话显示，清空显示过滤后再试。
- [ ] Wi-Fi 代理应保持为空，不要额外填写另一个代理。
- [ ] 在 DevEco Log 中查看 `CharlesVpnExt` 与 `charles_vpn`，检查 TUN 创建和 Native 错误。
- [ ] 先关闭再启动，排除 Charles 在运行中更换端口或地址导致的旧连接问题。

## E. HTTPS App 无法联网

这是当前明确限制，不是 SSL 证书配置遗漏。本应用不处理 HTTPS，非 HTTP/TLS 流会被拒绝。停止 VPN 后再恢复普通使用；不要通过安装不受信证书或绕过 Pinning 来解决本需求之外的问题。

## F. 域名无法解析，但 IP 明文 HTTP 可访问

- [ ] 检查系统 DNS 是否可达；Native 仅中继 UDP/53。
- [ ] 企业网的 DNS over TCP、定制 DNS 或 IPv6-only DNS 不在支持范围内。
- [ ] DNS 中继 socket 依赖 `protectProcessNet()`，确认启动日志中该调用成功且发生在 TUN 创建前。

## G. 启动成功，但其他 App 网络变慢或失败

- [ ] 默认 IPv4 路由会影响其他应用；只在调试期间开启。
- [ ] QUIC/UDP 被丢弃可能导致回退延迟，TLS 流可能被拒绝。
- [ ] 大请求体、大量并发、高吞吐不在精简用户态 TCP 的目标范围内。
- [ ] Charles 限流和长时间断点会直接影响响应；先关闭 Throttle/Breakpoints 做对照。

## H. 关闭失败或状态不一致

- [ ] 单次 Charles 连接错误不会把全局 VPN 标成停止；这是设计行为。
- [ ] 关闭必须等待扩展的 STOPPED 事件，超时不会虚报成功。
- [ ] 若系统已回收 VPN，界面可能显示断开；检查是否有其他 VPN 接管或系统资源回收。
- [ ] 重新打开 App 后如仍有异常，先在系统 VPN 设置中断开，再重启本 App。不要连续强制停止来替代正常生命周期排查。

## I. 历史记录问题

- [ ] 历史只在 Native READY 后保存，探测成功但未启动不会保存。
- [ ] 最多 10 条，同 IP+端口去重并置顶；不同端口属于不同记录。
- [ ] 若系统禁用了应用数据持久化或应用数据被清除，历史不会保留。
- [ ] 保存失败会显示 toast，不影响已运行的转发，但应检查应用存储状态。
