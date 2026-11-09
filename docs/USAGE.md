# Charles 配置与真机使用

## 一、Charles 电脑端一次性配置

以下配置只需完成一次。以后使用时，电脑只需启动 Charles，不需要运行任何脚本、HDC 命令、Flask 服务或其他转发程序。

1. **HTTP 代理端口**
   - 打开 Charles，进入 `Proxy > Proxy Settings`。
   - 将 HTTP proxy port 设置为 `8888`。
   - 开启 `Enable transparent HTTP proxying`（透明 HTTP 代理）。
   - 本应用不配置 SSL Proxying，不安装或处理 HTTPS 证书。
2. **Access Control**
   - 打开 `Proxy > Access Control Settings`。
   - 添加手机所在的真实局域网网段，例如电脑和手机都在 `192.168.1.x` 时添加 `192.168.1.0/24`。
   - 不要照搬示例网段，也不要为了方便长期允许 `0.0.0.0/0`。
   - 如果 Charles 弹出手机地址的接入确认，选择允许；预先配置网段后通常无需每次确认。
3. **电脑防火墙**
   - 允许 Charles 接收局域网入站连接，放行 TCP `8888`。
   - macOS 还需在防火墙的应用规则中允许 Charles 接受传入连接。
4. **局域网**
   - 手机与电脑连接同一局域网。
   - 路由器不能开启客户端/AP 隔离，访客网络可能阻止互访。
   - 在 App 中填写电脑的局域网 IPv4，不填 `127.0.0.1`，不填电脑公网地址。

## 二、DevEco 调试签名与安装

1. 用 DevEco Studio 打开工程根目录 `cli2api-flicker`。
2. 进入 `File > Project Structure > Signing Configs`，登录开发者账号并启用自动调试签名（Automatically generate signature）。
3. 连接已开启开发者调试的 HarmonyOS NEXT 真机，选择该设备。
4. 选择 `entry / default / debug`，点击 Run。DevEco 会生成签名 HAP、安装并启动。
5. 本工程目标与兼容版本均为 API 26，仅构建 `arm64-v8a`，不为旧系统提供回退实现。

> 当前仓库没有保存账号、私钥或调试 Profile，避免把个人签名材料提交到源码目录。自动签名生成的本地配置由 DevEco 管理。

## 三、日常使用

1. 确认手机的 **Wi-Fi 代理保持“无/空”**。不要同时配置系统 Wi-Fi 代理，否则可能形成重复代理或连接回环。
2. 电脑启动 Charles，手机打开本 App。
3. 输入 Charles 服务器 IP 和端口，默认端口 `8888`。
   - 点击【选择应用】，可直接选择内置的【快手】或【快手极速版】，也可选择【全部应用】。
   - 选择器支持按应用名称或 Bundle 搜索。其他应用首次在选择器底部添加一次显示名称和 Bundle，之后即保存为常用项；自定义项可长按删除。
   - 上次选择会持久保存。指定模式使用官方 `VpnConfig.trustedApplications`，不修改被代理应用本身。
   - 内置 Bundle：快手 `com.kuaishou.hmapp`；快手极速版 `com.kuaishou.hmnebula`。其他应用的 Bundle 可在其 `AppScope/app.json5` 中查看。
4. 可先点击【测试连通性】。该操作只建立 TCP 连接，1.5 秒超时，不发送 HTTP 数据。
5. 点击【一键启动代理】。启动前会再次进行 1.5 秒 TCP 探测，失败则直接终止，不进入 VPN 授权。
6. 首次使用时，在系统原生 VPN 授权弹窗中确认信任。
7. 只有 TUN fd 创建成功且 Native 工作线程运行后，界面才显示【运行中】，并提示“✅ 代理已启动，状态栏出现VPN图标”。
8. 在需要调试的 App 中访问**明文 HTTP** 地址，例如自己控制的 `http://...` 测试服务。Charles 应看到带绝对 URI 的标准 HTTP 代理请求。
9. 可在 Charles 中对明文 HTTP 请求使用 Breakpoints、Rewrite、Map Local 和 Throttle。Map Local 的响应会经 Native 原样分段写回 TUN。
10. 点击【一键关闭代理】，等待扩展确认后提示“✅ 代理已关闭”。

### 历史记录

- 启动成功后自动保存本次实际使用的 IP+端口，而不是输入框里尚未生效的新值。
- 新记录置顶、自动去重，最多 10 条。
- 点击记录：填充 IP 和端口。
- 长按记录：弹窗确认后删除。
- 【清空全部历史】：弹窗确认后删除全部。
- 使用 `@kit.ArkData preferences` 的 `put` + `flush` 持久化，只在 UI 进程访问，避免官方提示的多进程 Preferences 风险。

## 四、建议的真机验收顺序

1. 先用浏览器访问一个确定支持明文 HTTP 的内网测试地址。
2. 在 Charles 中确认请求方法、absolute URI、Host、请求头和 POST body。
3. 测试一个普通 GET，再测试带 `Content-Length` 的 POST 和 chunked POST。
4. 分别启用 Breakpoints、Rewrite、Map Local、Throttle，检查手机响应与延迟。
5. 测试重复启动/关闭、授权拒绝、Charles 中途退出、Wi-Fi 断开、长时间断点。
6. 最后重启 App，检查历史记录是否保留、去重和置顶是否正确。

> 主机测试无法替代以上真机步骤。当前交付尚未宣称这些真机项目已通过。
