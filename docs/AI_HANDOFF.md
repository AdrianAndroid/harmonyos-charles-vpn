# AI 交接摘要

更新日期：2026-11-09。

本文用于让下一位 AI 快速接续工作。详细设计和验收证据以 [VALIDATION.md](VALIDATION.md)、[USAGE.md](USAGE.md)、[RISKS.md](RISKS.md) 和 [TROUBLESHOOTING.md](TROUBLESHOOTING.md) 为准。本文整理时没有重新执行构建、主机测试或真机测试。

## 1. 当前项目与仓库

- 项目：HarmonyOS NEXT Stage 模型 HAP，通过官方 `VpnExtensionAbility` 创建 TUN，在 C++ 用户态 TCP 端点中将明文 HTTP/1.x 转为 Charles 标准代理请求。
- 不是 Wi-Fi 代理设置工具；手机 Wi-Fi 代理保持为空，电脑端只需运行 Charles，不需要脚本或辅助服务。
- 支持全局模式和基于 `VpnConfig.trustedApplications` 的单应用模式。
- 明确只支持明文 TCP HTTP/1.x；不要顺手加入 HTTPS、证书绕过、SSL Pinning 绕过或 QUIC 支持，并声称原需求已经覆盖。
- GitHub：<https://github.com/AdrianAndroid/harmonyos-charles-vpn>
- SSH 远程：`git@github.com:AdrianAndroid/harmonyos-charles-vpn.git`
- 本地目录名仍为 `cli2api-flicker`，与 GitHub 仓库名不同不影响使用。
- 首次上传提交：`b88d4199fd4725778ba18e72d4f12773f4ac70a0`，分支为 `main`，已设置跟踪 `origin/main`。

## 2. 已完成并有记录的成果

以下来自仓库已有验证记录：

- DevEco SDK `26.0.0.105` / HarmonyOS API 26，ArkTS 与 arm64 Native 构建成功。
- 签名 HAP：`entry/build/default/outputs/default/entry-default-signed.hap`。
- `tests/run_host_tests.sh` 已返回 `ALL HOST TESTS PASSED`，覆盖 HTTP 解析、分包组包、IPv4 分片、TCP 序号/重传及 socketpair 模拟 TUN 的端到端 GET。
- 真机已完成自动调试签名、安装、启动、VPN 授权、TUN 创建和 Native 启动。
- 已验证全局模式，以及 `com.zj.charlesvpn`、`com.kuaishou.hmapp` 的单应用模式；正常停止也已验证。
- 已修复签名配置未被 product 引用、修改包名后 `Want.bundleName` 不一致，以及系统快速回收 `:vpn` 进程导致 UI 卡在“正在关闭”的问题。
- 已重构为四 Tab（总览/流量/连接/设置）+ 悬浮底栏；“流量”页为整页可滚动会话列表：`LazyForEach` + `@Observed` 行内更新保证高频事件下的渲染性能，点击条目展开详情。Native 解析明文 HTTP/1.x 的请求/响应：Native 解析明文 HTTP/1.x 的请求/响应，经 `EVENT_TRAFFIC` 公共事件送到 UI，显示方法、Host/Path、状态码、请求/响应头、响应体前 1KB、字节数和耗时。主机端到端测试已断言 `flow/req/resp/body/close` 事件（含 chunked 响应）。

不要把“界面显示运行中”当作 Charles 全功能已经验收。

## 3. 可复用的成功经验

1. **以本机 SDK 声明和官方示例为准。** 使用 `VpnConnection.create(config)`、`VpnExtensionAbility`、`type: "vpn"` 和 `ohos.permission.INTERNET`；不要重新引入旧 `setUp()`、不存在的 `VPN_EXTENSION` 权限或系统级 `MANAGE_VPN`。
2. **严格保持启动顺序。** TCP 探测通过后启动扩展并完成用户授权；先 `protectProcessNet()`，再创建 TUN，随后把 fd 交给 Native；只有 Native 真正运行后才发送 READY、显示“运行中”并保存历史。
3. **关闭以真实生命周期事件为准。** 停止并 `join` Native 线程，关闭 fd/socket，再 `VpnConnection.destroy()`；等待扩展 STOPPED，不用超时虚报成功，也不通过强行保活规避系统生命周期。
4. **签名和包名一起检查。** 自动签名材料存在还不够，product 必须引用 `signingConfig`；修改 `bundleName` 时同步检查 Want 和调试 Profile。
5. **主机测试与真机验收分层。** 先跑解析器、TCP 引擎和集成测试，再做签名安装及报文级真机验证；主机测试通过不能证明 HarmonyOS TUN、授权、签名和 ArkTS 运行时都正常。
6. **持久化保持单进程。** Preferences 只在 UI 进程使用，历史仅在 READY 后保存；启动前探测成功但未实际运行时不保存。
7. **限制代理范围并保护凭据。** 调试时优先选择单个目标应用；Charles 只允许可信网段。`build-profile.json5` 含本机签名配置且已被忽略，不要强制提交账号、私钥、Profile 或密码。
8. **推送前先识别目标状态。** 本次目标为空仓库，使用 `git ls-remote` 确认后执行 `git remote set-url origin ...`、`git push -u origin main`，最后核对远程提交。GitHub CLI 当时未登录，但 SSH 可直接读写，普通 Git 推送不依赖 `gh auth login`。

## 4. 下次建议优先做的事

按 [USAGE.md](USAGE.md) 的验收顺序，逐项补充真实报文和设备证据：

1. Charles Breakpoints、Rewrite、Map Local、Throttle 的完整真机回归。
2. 普通 GET、`Content-Length` POST、chunked POST、keep-alive，以及响应分段写回。
3. 真机 DNS 中继、复杂 POST、乱序、弱网、大请求边界和长时间断点。
4. Charles 中途退出、Wi-Fi 切换、授权拒绝、其他 VPN 冲突、重复启停和应用重启。
5. 单应用与全局模式的对照测试，确认非目标应用不会进入单应用 VPN。
6. 在真机连接 Charles 后补做实时流量面板的显示/展开/清空回归；本次功能修改后设备断开，仅完成主机端到端与 HAP 编译验证。
7. 每完成一项，同步更新 [VALIDATION.md](VALIDATION.md)；未执行的项目继续明确列为未验证。

## 5. 常用命令

```sh
# 主机测试
tests/run_host_tests.sh

# 本机已使用过的 HAP 构建命令
DEVECO_SDK_HOME=/Applications/DevEco-Studio.app/Contents/sdk \
  /Applications/DevEco-Studio.app/Contents/tools/hvigor/bin/hvigorw \
  --mode module -p product=default -p module=entry@default \
  -p buildMode=debug assembleHap --no-daemon

# 开始修改前检查现场
git status --short --branch
git remote -v

# 推送前确认远程，避免覆盖不相关内容
git ls-remote origin
```

首次克隆且没有本地 `build-profile.json5` 时，先复制模板，再在 DevEco 中配置自动调试签名：

```sh
cp build-profile.example.json5 build-profile.json5
```

## 6. 接续原则

- 先读 README 和本文，再查看具体代码；不要重复推导已记录的 API 结论。
- 修改前检查工作区，保留用户已有改动；不要用强制推送覆盖远程历史。
- 修复后执行与改动相匹配的测试，并如实报告实际执行结果。
- 不将构建成功、TCP 探测成功或 VPN 图标出现等同于抓包功能验收成功。
