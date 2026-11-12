# 验证记录

日期：2026-11-09。

## 已核对

- DevEco 内置 SDK：HarmonyOS API 26，包版本 `26.0.0.105`。
- `@ohos.net.vpnExtension.d.ts`：`create(config): Promise<number>`、`protectProcessNet(): Promise<void>`、`createVpnObserver()`。
- `@ohos.app.ability.VpnExtensionAbility.d.ts`：`onCreate(want)` / `onDestroy()`。
- 官方三方 VPN 指南与官方 `VPNControl_Case` 示例的组件声明、启动顺序、fd 获取和 Native 接入。
- 当前 SDK `PermissionDefinitions.json` 与官方权限文档：三方扩展要求 `INTERNET`；没有 `ohos.permission.VPN_EXTENSION`。
- Node-API 官方线程安全函数与环境清理钩子用法。

## 已通过的主机测试

执行：

```sh
tests/run_host_tests.sh
```

结果：`ALL HOST TESTS PASSED`。

覆盖：

1. HTTP origin-form 到 absolute-form 的请求行转换。
2. 请求头跨 TCP 分片、多个请求合并、Content-Length、chunked 请求体。
3. 重复/冲突 Content-Length、Transfer-Encoding + Content-Length、重复 Host、CONNECT 的拒绝。
4. IPv4/TCP 校验和、分片缺口/重叠/超时、TCP 32 位序号回绕。
5. 使用 socketpair 模拟 TUN 与本地 TCP Charles 的端到端流程：SYN/SYNACK/ACK、GET 转换、响应 MSS 分段、实际重传、FIN、重复停止与参数校验。
6. 实时流量事件：同一条端到端 GET 上断言 `flow`、`req`（GET/example.com//）、`resp`（Content-Length 5）、`body`（base64 解码为 `hello`）和 `close` 事件均产生；chunked 响应也能解析出 `hello` 预览。

主机测试使用 macOS clang++，`-std=c++17 -Wall -Wextra -Werror`。它不能覆盖 HarmonyOS 的 TUN 驱动、系统授权、签名或真实 ArkTS 运行时。

## 已通过的工程构建与真机验证

执行 DevEco 自带 hvigor，结果为：

```text
:entry:default@BuildNativeWithNinja... Finished
:entry:default@CompileArkTS... Finished
:entry:default@PackageHap... Finished
:entry:default@SignHap... Finished
BUILD SUCCESSFUL
```

最终产物：

```text
entry/build/default/outputs/default/entry-default-signed.hap
entry/build/default/intermediates/libs/default/arm64-v8a/libcharles_vpn.so
```

最终签名 HAP 的 SHA-256：

```text
4c6e742a7dd3b6f96e418f7f3490b550ddffbfe826a3721f75be933f0ac46cae
```

真机已验证：

- 自动调试签名、HAP 安装和 `EntryAbility` 启动成功。
- 使用 `172.24.121.94:8888` 的 TCP 探测、VPN 信任授权、TUN 创建和 Native 启动成功，界面显示“运行中”，历史记录已保存。
- 单应用模式填写真实 Bundle `com.zj.charlesvpn` 后，界面显示“运行中 · 仅 com.zj.charlesvpn”，扩展日志出现 `VPN TUN proxy started`。
- 单应用正常关闭已验证，最终界面恢复“已停止”。
- 常用应用选择器已签名安装，内置快手 `com.kuaishou.hmapp` 和快手极速版 `com.kuaishou.hmnebula`；真机界面已显示“运行中 · 仅 com.kuaishou.hmapp”。
- 修复了签名材料存在但 product 未引用 `signingConfig` 导致输出 unsigned HAP 的问题，以及包名修改后 Want.bundleName 不一致的问题。
- 修复了系统快速销毁 `:vpn` 进程时 STOPPED 事件过晚、UI 卡在“正在关闭”的生命周期问题，并在修复后重新完成启停测试。

## 尚未逐项验证

- Charles 的 Breakpoints、Rewrite、Map Local、Throttle 的完整真机回归。
- 真机 DNS 中继、复杂 POST/keep-alive、乱序和弱网行为。
- Charles 中途关闭、Wi-Fi 切换、长时间断点和应用重启后的更多边界场景。
- 其他目标 Bundle 与多个被测 App 的范围对照测试；当前已用本应用的真实 Bundle 验证官方 `trustedApplications` 配置链路。
- 实时流量面板修改后的真机端到端显示：本次修改完成后测试设备已断开，仅完成 Native 事件的主机端到端断言和 HAP 编译；需在真机连接 Charles 后补一次面板实测。
