# Charles 局域网抓包代理（HarmonyOS NEXT VPN 模式）

这是一个仅用于真机调试的 HarmonyOS NEXT Stage 模型 HAP 工程。应用通过官方 `VpnExtensionAbility` 创建 TUN 虚拟网卡，在 C++ 用户态 TCP 端点中把明文 HTTP/1.x 请求转换为标准代理 absolute-form，再发送到局域网 Charles。**它不是 Wi-Fi 代理设置工具，不使用剪贴板，也不需要电脑运行脚本或辅助服务。**

## 当前交付状态

- HarmonyOS API 26 ArkTS 与 arm64 Native 编译：`BUILD SUCCESSFUL`。
- 签名 HAP：`entry/build/default/outputs/default/entry-default-signed.hap`。
- 已在 API 26 真机完成签名安装和应用启动，VPN 界面已显示“运行中”并保存 Charles 历史记录。
- 主机测试：HTTP 分包/组包、请求头重写、IPv4 分片、TCP 握手/ACK/重传、模拟 TUN 端到端 GET 均通过。
- 支持可搜索的常用应用选择器：内置快手、快手极速版，可添加自定义常用项并记住上次选择；指定应用时使用官方 `VpnConfig.trustedApplications`，选择“全部应用”则为全局模式。
- Charles 断点、rewrite、map local、限流的逐项真机回归仍应在使用时按文档验证，不以“VPN 已运行”替代报文级验收。

验证记录见 [docs/VALIDATION.md](docs/VALIDATION.md)。

## 1. 工程目录树

```text
cli2api-flicker/
├── AppScope/
│   ├── app.json5                         # bundleName、版本、图标和名称
│   └── resources/base/                   # 应用级资源
├── entry/
│   ├── build-profile.json5               # Native CMake 入口
│   ├── oh-package.json5                  # NAPI 类型包依赖
│   └── src/main/
│       ├── module.json5                  # UIAbility、VPN Extension、INTERNET
│       ├── cpp/
│       │   ├── CMakeLists.txt            # HarmonyOS Native 构建脚本
│       │   ├── vpn_napi.cpp              # NAPI 导出、TSFN、生命周期清理
│       │   ├── tun_proxy.h/.cpp          # TUN、TCP、UDP DNS、poll 转发核心
│       │   ├── http_request.h/.cpp       # HTTP/1.x 解析和 absolute-form 转换
│       │   └── types/libcharles_vpn/     # ArkTS 可见的 NAPI 声明
│       ├── ets/
│       │   ├── entryability/EntryAbility.ets
│       │   ├── vpnability/CharlesVpnExtensionAbility.ets
│       │   ├── common/NativeVpn.ets
│       │   ├── common/VpnEvents.ets       # UI 与扩展跨进程状态事件
│       │   └── pages/Index.ets            # 完整 UI、探测、历史记录和状态
│       └── resources/base/               # 页面、字符串、颜色、图标
├── tests/
│   ├── http_request_test.cpp
│   ├── engine_test.cpp
│   ├── integration_test.cpp              # socketpair 模拟 TUN 的端到端测试
│   └── run_host_tests.sh
├── build-profile.json5                   # compile/target/compatible 26.0.0
├── docs/
│   ├── USAGE.md                          # Charles、签名、真机使用步骤
│   ├── RISKS.md                          # 方案差异、限制与风险
│   ├── TROUBLESHOOTING.md                # 故障排查清单
│   └── VALIDATION.md                     # 已执行验证与待验收项
└── README.md
```

## 2. 官方接口与权限核对

本工程以 DevEco Studio 自带 **26.0.0.105 / API 26** SDK 的实际声明为编译基线，并交叉阅读官方文档及官方 VPN 示例：

- [HarmonyOS：连接 VPN](https://developer.huawei.com/consumer/cn/doc/harmonyos-guides/net-vpnExtension)
- [OpenHarmony 官方文档源码：net-vpnExtension.md](https://github.com/openharmony/docs/blob/master/zh-cn/application-dev/network/net-vpnExtension.md)
- [官方 VPN API：js-apis-net-vpnExtension.md](https://github.com/openharmony/docs/blob/master/zh-cn/application-dev/reference/apis-network-kit/js-apis-net-vpnExtension.md)
- [官方 VPN 示例应用](https://github.com/openharmony/applications_app_samples/tree/master/code/DocsSample/NetWork_Kit/NetWorkKit_NetManager/VPNControl_Case)
- [官方 Node-API 线程安全开发](https://github.com/openharmony/docs/blob/master/zh-cn/application-dev/napi/use-napi-thread-safety.md)
- [官方 Node-API 环境清理钩子](https://github.com/openharmony/docs/blob/master/zh-cn/application-dev/napi/use-napi-about-cleanuphook.md)

关键结论：

1. 最新公开创建接口是 `VpnConnection.create(config): Promise<number>`，返回 TUN fd；没有使用旧 `setUp()`。
2. 启动入口是 `vpnExtension.startVpnExtensionAbility(want)`，扩展组件在 `module.json5` 中声明为 `type: "vpn"`。
3. 官方三方 VPN 指南明确要求 `ohos.permission.INTERNET`。当前 API 26 权限表中**不存在** `ohos.permission.VPN_EXTENSION`，因此没有配置这个无效名称。
4. `ohos.permission.MANAGE_VPN` 用于另一组系统 VPN 管理接口，是 `system_basic / SYSTEM` 权限；普通三方 VPN Extension 不应额外申请它。
5. 使用 API 22+ 的 `protectProcessNet()` 保护 VPN 扩展进程，防止到 Charles/DNS 的出站连接重新进入 TUN。目标与兼容版本均固定为 API 26，不做旧版本回退。
6. VPN 信任授权是系统原生弹窗，不是 `INTERNET` 运行时权限弹窗；首次信任后由系统管理授权状态。
7. `attachTunFd` 与 `setVpnEventCallback` 是官方 fd 接入和错误通知所需的内部 NAPI 桥接；需求指定的 `startVpnProxy`、`stopVpnProxy`、`isVpnRunning` 三个公开控制方法均保留。

## 3. NAPI 与转发接口

```ts
startVpnProxy(targetIp: string, targetPort: number): void
stopVpnProxy(): void
isVpnRunning(): boolean

// 扩展生命周期内部桥接
attachTunFd(tunFd: number): void
setVpnEventCallback(callback: ((message: string) => void) | null): void
```

启动顺序：

```text
UI 进行 1.5 秒 TCP 探测
  → startVpnExtensionAbility(want)
  → 系统 VPN 信任授权
  → VpnExtensionAbility.onCreate
  → protectProcessNet()
  → VpnConnection.create(config) 取得 TUN fd
  → attachTunFd(fd) 启动 C++ poll 工作线程
  → 发送 READY 事件，UI 保存历史并提示成功
```

关闭顺序：先停止 Native 工作线程、唤醒并 `join`、关闭 Native `dup` 的 TUN fd 和所有 socket，再调用 `VpnConnection.destroy()` 销毁原始 VPN 会话。

## 4. 构建

首次从 Git 克隆时，如果根目录没有 `build-profile.json5`，先执行：

```sh
cp build-profile.example.json5 build-profile.json5
```

然后用 DevEco Studio 打开工程根目录并配置自动调试签名。`build-profile.json5` 被 `.gitignore` 排除，避免签名路径、`keyPassword`、`storePassword` 等本机凭据进入仓库；不要强行添加该文件。当前开发机上的本地配置不受影响。

等待同步完成后选择 `entry` 的 `default` 产品和 `debug` 模式，执行 **Build > Build Hap(s)/APP(s)**。

本机已实际执行的等效命令：

```sh
DEVECO_SDK_HOME=/Applications/DevEco-Studio.app/Contents/sdk \
  /Applications/DevEco-Studio.app/Contents/tools/hvigor/bin/hvigorw \
  --mode module -p product=default -p module=entry@default \
  -p buildMode=debug assembleHap --no-daemon
```

运行 Native 主机测试：

```sh
tests/run_host_tests.sh
```

真机安装前必须按 [docs/USAGE.md](docs/USAGE.md) 配置自动调试签名。未签名构建成功不等于可安装。

## 5. 配套文档

- [Charles 一次性配置与真机使用](docs/USAGE.md)
- [方案风险与限制](docs/RISKS.md)
- [常见故障排查](docs/TROUBLESHOOTING.md)
- [构建和测试验证记录](docs/VALIDATION.md)
