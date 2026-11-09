import { common, Want } from '@kit.AbilityKit';
import { preferences } from '@kit.ArkData';
import { socket, vpnExtension } from '@kit.NetworkKit';
import { BusinessError, commonEventManager } from '@kit.BasicServicesKit';
import {
  BUNDLE_NAME,
  EVENT_ERROR,
  EVENT_READY,
  EVENT_STOPPED,
  VPN_ABILITY_NAME,
  VPN_EVENT
} from '../common/VpnEvents';

interface ProxyRecord {
  ip: string;
  port: number;
}

interface CommonAppRecord {
  name: string;
  bundleName: string;
  builtIn: boolean;
}

type ProxyStatus = 'stopped' | 'checking' | 'starting' | 'running' | 'stopping';

const HISTORY_KEY: string = 'records';
const COMMON_APPS_KEY: string = 'common_apps';
const SELECTED_APP_BUNDLE_KEY: string = 'selected_app_bundle';
const SELECTED_APP_NAME_KEY: string = 'selected_app_name';
const DEFAULT_COMMON_APPS: CommonAppRecord[] = [
  { name: '快手', bundleName: 'com.kuaishou.hmapp', builtIn: true },
  { name: '快手极速版', bundleName: 'com.kuaishou.hmnebula', builtIn: true }
];
const CONNECT_ERROR: string = '无法连接Charles，检查Charles是否开启、局域网、Access Control、防火墙放行8888端口';

function errorText(error: Object): string {
  const businessError = error as BusinessError;
  return businessError.message ?? String(error);
}

function isValidIpv4(ip: string): boolean {
  const parts: string[] = ip.split('.');
  if (parts.length !== 4) {
    return false;
  }
  return parts.every((part: string) => {
    if (!/^\d{1,3}$/.test(part) || (part.length > 1 && part.startsWith('0'))) {
      return false;
    }
    const value: number = Number(part);
    return value >= 0 && value <= 255;
  });
}

@Entry
@Component
struct Index {
  @State private targetIp: string = '';
  @State private targetPort: string = '8888';
  @State private targetBundle: string = '';
  @State private activeBundle: string = '';
  @State private selectedAppName: string = '';
  @State private commonApps: CommonAppRecord[] = DEFAULT_COMMON_APPS;
  @State private showAppPicker: boolean = false;
  @State private appSearch: string = '';
  @State private newAppName: string = '';
  @State private newAppBundle: string = '';
  @State private status: ProxyStatus = 'stopped';
  @State private records: ProxyRecord[] = [];
  @State private busy: boolean = false;
  @State private initializing: boolean = true;
  @State private lastError: string = '';
  private store?: preferences.Preferences;
  private subscriber?: commonEventManager.CommonEventSubscriber;
  private authorizationObserver?: vpnExtension.VpnObserver;
  private readyResolve?: () => void;
  private readyReject?: (reason: Error) => void;
  private stoppedResolve?: () => void;
  private stopRequested: boolean = false;
  private startWatchdog?: number;
  private startingRecord?: ProxyRecord;
  private startingBundle: string = '';

  aboutToAppear(): void {
    void this.initialize();
  }

  aboutToDisappear(): void {
    if (this.subscriber) {
      commonEventManager.unsubscribe(this.subscriber);
      this.subscriber = undefined;
    }
    this.authorizationObserver?.offAuthorizationResult();
    this.authorizationObserver = undefined;
    if (this.startWatchdog !== undefined) {
      clearTimeout(this.startWatchdog);
      this.startWatchdog = undefined;
    }
  }

  private async initialize(): Promise<void> {
    try {
      const context = this.getUIContext().getHostContext() as common.UIAbilityContext;
      this.store = await preferences.getPreferences(context, { name: 'charles_proxy_history' });
      const raw: string = await this.store.get(HISTORY_KEY, '[]') as string;
      const decoded = JSON.parse(raw) as ProxyRecord[];
      this.records = decoded.filter((record: ProxyRecord) =>
        isValidIpv4(record.ip) && Number.isInteger(record.port) && record.port > 0 && record.port <= 65535
      ).slice(0, 10);
      if (this.records.length > 0) {
        this.targetIp = this.records[0].ip;
        this.targetPort = String(this.records[0].port);
      }

      const rawApps: string = await this.store.get(COMMON_APPS_KEY, '[]') as string;
      const customApps = (JSON.parse(rawApps) as CommonAppRecord[]).filter((app: CommonAppRecord) =>
        typeof app.name === 'string' && typeof app.bundleName === 'string' && app.bundleName.length > 0
      ).map((app: CommonAppRecord) => {
        app.builtIn = false;
        return app;
      });
      this.commonApps = [...DEFAULT_COMMON_APPS, ...customApps.filter((custom: CommonAppRecord) =>
        !DEFAULT_COMMON_APPS.some((builtIn: CommonAppRecord) => builtIn.bundleName === custom.bundleName)
      )].slice(0, 50);
      this.targetBundle = await this.store.get(SELECTED_APP_BUNDLE_KEY, '') as string;
      this.selectedAppName = await this.store.get(SELECTED_APP_NAME_KEY, '') as string;

      this.subscriber = await commonEventManager.createSubscriber({
        events: [VPN_EVENT],
        publisherBundleName: BUNDLE_NAME
      });
      await commonEventManager.subscribeToEvent(this.subscriber,
        (event: commonEventManager.CommonEventData) => {
          void this.handleVpnEvent(event);
        });

      // API 26 的官方授权结果回调；拒绝时不会进入可工作的 TUN 状态。
      this.authorizationObserver = vpnExtension.createVpnObserver();
      this.authorizationObserver.onAuthorizationResult((granted: boolean) => {
        if (!granted) {
          this.failPendingStart(new Error('VPN授权被拒绝'));
        }
      });
    } catch (error) {
      this.lastError = `初始化失败：${errorText(error as Object)}`;
      this.toast(this.lastError);
    } finally {
      this.initializing = false;
    }
  }

  private async handleVpnEvent(event: commonEventManager.CommonEventData): Promise<void> {
    if (event.event !== VPN_EVENT) {
      return;
    }
    if (event.code === EVENT_READY) {
      this.status = 'running';
      this.activeBundle = this.startingBundle;
      this.busy = false;
      this.lastError = '';
      const resolve = this.readyResolve;
      this.clearPendingStart();
      resolve?.();
      await this.rememberCurrentTarget();
      this.toast('✅ 代理已启动，状态栏出现VPN图标');
      return;
    }
    if (event.code === EVENT_STOPPED) {
      const wasStopping: boolean = this.stopRequested || this.status === 'stopping';
      const wasRunning: boolean = this.status === 'running';
      this.status = 'stopped';
      this.activeBundle = '';
      this.busy = false;
      const resolve = this.stoppedResolve;
      this.stoppedResolve = undefined;
      resolve?.();
      this.stopRequested = false;
      if (wasStopping) {
        this.toast('✅ 代理已关闭');
      } else if (wasRunning && !this.readyReject) {
        this.toast('VPN代理已断开');
      }
      this.failPendingStart(new Error('VPN扩展已停止'));
      return;
    }
    if (event.code === EVENT_ERROR) {
      const rawMessage: string = event.data ?? '未知转发错误';
      const fatal: boolean = rawMessage.startsWith('fatal:');
      const message: string = fatal ? rawMessage.substring(6) : rawMessage;
      this.lastError = message;
      this.toast(`转发错误：${message}`);

      // 单条 Charles 连接失败不等于 VPN 已停止；保持运行状态并允许后续流重试。
      if (!fatal && (this.status === 'running' || this.status === 'stopping')) {
        return;
      }
      this.status = 'stopped';
      this.activeBundle = '';
      this.busy = false;
      this.stopRequested = false;
      this.failPendingStart(new Error(message));
      const resolve = this.stoppedResolve;
      this.stoppedResolve = undefined;
      resolve?.();
      if (fatal) {
        try {
          await vpnExtension.stopVpnExtensionAbility(this.vpnWant());
        } catch (_) {
          // Native 已退出；系统会话可能也已由系统回收。
        }
      }
    }
  }

  private validateTarget(): boolean {
    const port: number = Number(this.targetPort);
    if (!isValidIpv4(this.targetIp)) {
      this.toast('请输入有效的Charles IPv4地址');
      return false;
    }
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      this.toast('端口必须是1到65535之间的整数');
      return false;
    }
    return true;
  }

  private async probeCharles(): Promise<boolean> {
    let tcp: socket.TCPSocket | undefined;
    try {
      tcp = socket.constructTCPSocketInstance();
      await tcp.connect({
        address: {
          address: this.targetIp,
          port: Number(this.targetPort),
          family: 1
        },
        // 官方 TCPConnectOptions.timeout，单位毫秒；connect 同时负责隐式 bind。
        timeout: 1500
      });
      return true;
    } catch (error) {
      this.lastError = errorText(error as Object);
      return false;
    } finally {
      if (tcp) {
        try {
          await tcp.close();
        } catch (_) {
          // 探测结果已确定；关闭失败的连接不会再用于启动。
        }
      }
    }
  }

  private showConnectFailure(): void {
    this.getUIContext().showAlertDialog({
      title: '连接失败',
      message: CONNECT_ERROR,
      confirm: {
        value: '知道了',
        action: () => {
        }
      }
    });
  }

  private async testConnectivity(): Promise<void> {
    if (this.busy || this.status === 'running' || !this.validateTarget()) {
      return;
    }
    this.busy = true;
    this.status = 'checking';
    const reachable: boolean = await this.probeCharles();
    this.busy = false;
    this.status = 'stopped';
    if (reachable) {
      this.toast(`✅ 已连接Charles ${this.targetIp}:${this.targetPort}`);
    } else {
      this.showConnectFailure();
    }
  }

  private vpnWant(): Want {
    return {
      deviceId: '',
      bundleName: BUNDLE_NAME,
      abilityName: VPN_ABILITY_NAME,
      parameters: {
        targetIp: this.startingRecord?.ip ?? this.targetIp,
        targetPort: this.startingRecord?.port ?? Number(this.targetPort),
        targetBundle: this.startingBundle
      }
    };
  }

  private async toggleProxy(): Promise<void> {
    if (this.busy || this.initializing) {
      return;
    }
    if (this.status === 'running') {
      await this.stopProxy();
    } else {
      await this.startProxy();
    }
  }

  private async startProxy(): Promise<void> {
    if (!this.validateTarget()) {
      return;
    }
    const bundleName: string = this.targetBundle.trim();
    if (bundleName.length > 255 || (bundleName.length > 0 && !/^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)*$/.test(bundleName))) {
      this.toast('Bundle名称只能包含字母、数字、下划线和点，且需以字母开头');
      return;
    }
    this.busy = true;
    this.status = 'checking';
    this.lastError = '';
    this.startingRecord = { ip: this.targetIp, port: Number(this.targetPort) };
    this.startingBundle = bundleName;

    // 必须先探测，失败则不调用 VPN 启动接口，也不会弹系统授权框。
    if (!await this.probeCharles()) {
      this.busy = false;
      this.status = 'stopped';
      this.startingRecord = undefined;
      this.startingBundle = '';
      this.showConnectFailure();
      return;
    }

    this.status = 'starting';
    const ready = new Promise<void>((resolve, reject) => {
      this.readyResolve = resolve;
      this.readyReject = reject;
    });
    this.startWatchdog = setTimeout(() => {
      this.failPendingStart(new Error('VPN启动超时，请检查系统VPN状态'));
    }, 12000);

    try {
      // INTERNET 是 system_grant，不做运行时权限弹窗；此处弹的是系统原生 VPN 信任授权。
      await vpnExtension.startVpnExtensionAbility(this.vpnWant());
      await ready;
      // 成功 toast 与历史保存由 EVENT_READY 驱动，确保 Native 已运行。
    } catch (error) {
      const message: string = errorText(error as Object);
      this.lastError = message;
      this.status = 'stopped';
      this.busy = false;
      this.clearPendingStart();
      this.startingRecord = undefined;
      this.startingBundle = '';
      this.toast(message.includes('授权被拒绝') ? message : `启动代理失败：${message}`);
      try {
        await vpnExtension.stopVpnExtensionAbility(this.vpnWant());
      } catch (_) {
        // 授权拒绝或启动未完成时，系统可能不存在可停止的会话。
      }
    }
  }

  private async stopProxy(): Promise<void> {
    this.busy = true;
    this.status = 'stopping';
    this.stopRequested = true;
    const stopped = new Promise<void>((resolve) => {
      this.stoppedResolve = resolve;
    });
    let watchdog: number | undefined;
    const timeout = new Promise<void>((_, reject) => {
      watchdog = setTimeout(() => reject(new Error('关闭代理超时')), 8000);
    });
    try {
      await Promise.race([vpnExtension.stopVpnExtensionAbility(this.vpnWant()), timeout]);
      // stopVpnExtensionAbility 返回前，onDestroy 已同步执行 Native stop。
      // :vpn 进程可能随后立即退出，因此即使 STOPPED 事件来不及送达，也不能卡在“正在关闭”。
      if (this.status === 'stopping') {
        this.status = 'stopped';
        this.activeBundle = '';
        this.busy = false;
        this.stopRequested = false;
        this.stoppedResolve = undefined;
        this.toast('✅ 代理已关闭');
      } else {
        await stopped;
      }
    } catch (error) {
      this.stopRequested = false;
      this.stoppedResolve = undefined;
      this.lastError = errorText(error as Object);
      this.toast(`关闭代理失败：${this.lastError}`);
      // 未收到扩展确认时保持运行状态，不虚报“已关闭”。
      this.status = 'running';
      this.busy = false;
    } finally {
      if (watchdog !== undefined) {
        clearTimeout(watchdog);
      }
    }
  }

  private filteredCommonApps(): CommonAppRecord[] {
    const query: string = this.appSearch.trim().toLowerCase();
    if (query.length === 0) {
      return this.commonApps;
    }
    return this.commonApps.filter((app: CommonAppRecord) =>
      app.name.toLowerCase().includes(query) || app.bundleName.toLowerCase().includes(query)
    );
  }

  private async selectApp(app: CommonAppRecord): Promise<void> {
    this.targetBundle = app.bundleName;
    this.selectedAppName = app.name;
    this.showAppPicker = false;
    this.appSearch = '';
    await this.persistSelectedApp();
  }

  private async selectAllApps(): Promise<void> {
    this.targetBundle = '';
    this.selectedAppName = '';
    this.showAppPicker = false;
    this.appSearch = '';
    await this.persistSelectedApp();
  }

  private async persistSelectedApp(): Promise<void> {
    if (!this.store) {
      return;
    }
    try {
      await this.store.put(SELECTED_APP_BUNDLE_KEY, this.targetBundle);
      await this.store.put(SELECTED_APP_NAME_KEY, this.selectedAppName);
      await this.store.flush();
    } catch (error) {
      this.toast(`应用选择保存失败：${errorText(error as Object)}`);
    }
  }

  private async addCommonApp(): Promise<void> {
    const bundleName: string = this.newAppBundle.trim();
    if (bundleName.length === 0 || bundleName.length > 255 ||
      !/^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)*$/.test(bundleName)) {
      this.toast('请输入有效的应用Bundle名称');
      return;
    }
    const existing = this.commonApps.find((app: CommonAppRecord) => app.bundleName === bundleName);
    if (existing) {
      this.newAppName = '';
      this.newAppBundle = '';
      await this.selectApp(existing);
      return;
    }
    let name: string = this.newAppName.trim();
    if (name.length === 0) {
      name = bundleName.substring(bundleName.lastIndexOf('.') + 1);
    }
    const app: CommonAppRecord = { name: name, bundleName: bundleName, builtIn: false };
    this.commonApps = [...this.commonApps, app].slice(0, 50);
    this.newAppName = '';
    this.newAppBundle = '';
    await this.persistCommonApps();
    await this.selectApp(app);
  }

  private async persistCommonApps(): Promise<void> {
    if (!this.store) {
      return;
    }
    try {
      const customApps = this.commonApps.filter((app: CommonAppRecord) => !app.builtIn);
      await this.store.put(COMMON_APPS_KEY, JSON.stringify(customApps));
      await this.store.flush();
    } catch (error) {
      this.toast(`常用应用保存失败：${errorText(error as Object)}`);
    }
  }

  private confirmRemoveCommonApp(app: CommonAppRecord): void {
    if (app.builtIn) {
      this.toast('内置常用应用不可删除');
      return;
    }
    this.getUIContext().showAlertDialog({
      title: '删除常用应用',
      message: `确定从常用列表删除“${app.name}”吗？`,
      primaryButton: {
        value: '取消',
        action: () => {
        }
      },
      secondaryButton: {
        value: '删除',
        fontColor: '#FFD53333',
        action: () => {
          this.commonApps = this.commonApps.filter((item: CommonAppRecord) =>
            item.bundleName !== app.bundleName
          );
          void this.persistCommonApps();
        }
      }
    });
  }

  private failPendingStart(error: Error): void {
    const reject = this.readyReject;
    this.clearPendingStart();
    reject?.(error);
  }

  private clearPendingStart(): void {
    this.readyResolve = undefined;
    this.readyReject = undefined;
    if (this.startWatchdog !== undefined) {
      clearTimeout(this.startWatchdog);
      this.startWatchdog = undefined;
    }
  }

  private async rememberCurrentTarget(): Promise<void> {
    const current: ProxyRecord = this.startingRecord ?? { ip: this.targetIp, port: Number(this.targetPort) };
    this.startingRecord = undefined;
    this.records = [current, ...this.records.filter((record: ProxyRecord) =>
      record.ip !== current.ip || record.port !== current.port
    )].slice(0, 10);
    await this.persistRecords();
  }

  private async persistRecords(): Promise<void> {
    if (!this.store) {
      return;
    }
    try {
      await this.store.put(HISTORY_KEY, JSON.stringify(this.records));
      await this.store.flush();
    } catch (error) {
      this.toast(`历史记录保存失败：${errorText(error as Object)}`);
    }
  }

  private deleteRecord(record: ProxyRecord): void {
    this.getUIContext().showAlertDialog({
      title: '删除历史记录',
      message: `确定删除 ${record.ip}:${record.port} 吗？`,
      primaryButton: {
        value: '取消',
        action: () => {
        }
      },
      secondaryButton: {
        value: '删除',
        fontColor: '#FFD53333',
        action: () => {
          this.records = this.records.filter((item: ProxyRecord) =>
            item.ip !== record.ip || item.port !== record.port
          );
          void this.persistRecords();
        }
      }
    });
  }

  private confirmClearHistory(): void {
    if (this.records.length === 0) {
      return;
    }
    this.getUIContext().showAlertDialog({
      title: '清空全部历史',
      message: '确定删除全部Charles代理记录吗？',
      primaryButton: {
        value: '取消',
        action: () => {
        }
      },
      secondaryButton: {
        value: '全部清空',
        fontColor: '#FFD53333',
        action: () => {
          this.records = [];
          void this.persistRecords();
        }
      }
    });
  }

  private toast(message: string): void {
    try {
      this.getUIContext().getPromptAction().showToast({ message: message, duration: 2500 });
    } catch (error) {
      console.error(`Toast failed: ${errorText(error as Object)}`);
    }
  }

  private statusText(): string {
    switch (this.status) {
      case 'running':
        return this.activeBundle.length > 0 ? `运行中 · 仅 ${this.activeBundle}` : '运行中 · 全部应用';
      case 'checking':
        return '正在检测连通性';
      case 'starting':
        return '正在启动（等待系统授权/TUN）';
      case 'stopping':
        return '正在关闭';
      default:
        return '已停止';
    }
  }

  private statusColor(): string {
    return this.status === 'running' ? '#FF16865C' : '#FF626B76';
  }

  @Builder
  private appPickerSheet() {
    Column({ space: 12 }) {
      Row() {
        Text('选择要代理的应用')
          .fontSize(22)
          .fontWeight(FontWeight.Bold)
          .layoutWeight(1)
        Button('完成')
          .fontSize(14)
          .height(34)
          .onClick(() => {
            this.showAppPicker = false;
          })
      }
      .width('100%')

      TextInput({ placeholder: '搜索应用名称或Bundle', text: this.appSearch })
        .type(InputType.Normal)
        .height(44)
        .onChange((value: string) => {
          this.appSearch = value;
        })

      Row() {
        Column({ space: 3 }) {
          Text('全部应用')
            .fontSize(17)
            .fontWeight(FontWeight.Medium)
          Text('不设置 trustedApplications，保持全局代理')
            .fontSize(12)
            .fontColor('#FF838B98')
        }
        .alignItems(HorizontalAlign.Start)
        .layoutWeight(1)
        Text(this.targetBundle.length === 0 ? '当前选择' : '选择')
          .fontSize(14)
          .fontColor('#FF246BCE')
      }
      .width('100%')
      .padding(12)
      .backgroundColor(this.targetBundle.length === 0 ? '#FFE8F1FF' : '#FFF4F6FA')
      .borderRadius(10)
      .onClick(() => {
        void this.selectAllApps();
      })

      List({ space: 8 }) {
        ForEach(this.filteredCommonApps(), (app: CommonAppRecord) => {
          ListItem() {
            Row() {
              Column({ space: 4 }) {
                Text(app.name)
                  .fontSize(17)
                  .fontWeight(FontWeight.Medium)
                Text(app.bundleName)
                  .fontSize(12)
                  .fontColor('#FF697386')
              }
              .alignItems(HorizontalAlign.Start)
              .layoutWeight(1)

              Text(app.builtIn ? '内置' : '长按删除')
                .fontSize(12)
                .fontColor('#FF9299A5')
              Text(this.targetBundle === app.bundleName ? '当前选择' : '选择')
                .fontSize(14)
                .fontColor('#FF246BCE')
                .margin({ left: 12 })
            }
            .width('100%')
            .padding(12)
            .backgroundColor(this.targetBundle === app.bundleName ? '#FFE8F1FF' : '#FFFFFFFF')
            .borderRadius(10)
            .onClick(() => {
              void this.selectApp(app);
            })
            .gesture(LongPressGesture().onAction(() => {
              this.confirmRemoveCommonApp(app);
            }))
          }
        }, (app: CommonAppRecord) => app.bundleName)
      }
      .width('100%')
      .layoutWeight(1)
      .scrollBar(BarState.Auto)

      Divider()
      Text('添加其他常用应用（仅需添加一次）')
        .fontSize(15)
        .fontWeight(FontWeight.Medium)
        .width('100%')
      TextInput({ placeholder: '应用显示名称（可留空）', text: this.newAppName })
        .type(InputType.Normal)
        .height(42)
        .onChange((value: string) => {
          this.newAppName = value;
        })
      TextInput({ placeholder: '应用Bundle，例如 com.example.app', text: this.newAppBundle })
        .type(InputType.Normal)
        .height(42)
        .onChange((value: string) => {
          this.newAppBundle = value.trim();
        })
      Button('添加并选择')
        .width('100%')
        .height(42)
        .enabled(this.newAppBundle.trim().length > 0)
        .onClick(() => {
          void this.addCommonApp();
        })
    }
    .width('100%')
    .height('100%')
    .padding(20)
    .backgroundColor('#FFF4F6FA')
  }

  @Builder
  private historyRow(record: ProxyRecord) {
    Row() {
      Column({ space: 4 }) {
        Text(`${record.ip}:${record.port}`)
          .fontSize(17)
          .fontColor('#FF17233D')
        Text('点击填充 · 长按删除')
          .fontSize(12)
          .fontColor('#FF8A919D')
      }
      .alignItems(HorizontalAlign.Start)
      .layoutWeight(1)

      Text('使用')
        .fontSize(14)
        .fontColor('#FF326BDB')
    }
    .width('100%')
    .padding(14)
    .backgroundColor('#FFFFFFFF')
    .borderRadius(10)
    .onClick(() => {
      this.targetIp = record.ip;
      this.targetPort = String(record.port);
    })
    .gesture(LongPressGesture().onAction(() => {
      this.deleteRecord(record);
    }))
  }

  build() {
    Column() {
      Scroll() {
        Column({ space: 18 }) {
          Text('Charles局域网抓包代理（VPN模式）')
            .fontSize(24)
            .fontWeight(FontWeight.Bold)
            .fontColor('#FF14213D')
            .width('100%')

          Text('VPN Extension · TUN · 仅明文TCP HTTP')
            .fontSize(13)
            .fontColor('#FF697386')
            .width('100%')

          Row({ space: 10 }) {
            Circle()
              .width(10)
              .height(10)
              .fill(this.statusColor())
            Text(`当前代理状态：${this.statusText()}`)
              .fontSize(17)
              .fontWeight(FontWeight.Medium)
              .fontColor(this.statusColor())
          }
          .width('100%')
          .padding(14)
          .backgroundColor('#FFFFFFFF')
          .borderRadius(12)

          Column({ space: 12 }) {
            Text('Charles服务器IP')
              .fontSize(14)
              .fontColor('#FF515B6C')
              .width('100%')
            TextInput({ placeholder: '例如 192.168.1.100', text: this.targetIp })
              .type(InputType.Normal)
              .height(48)
              .backgroundColor('#FFFFFFFF')
              .onChange((value: string) => {
                this.targetIp = value.trim();
              })

            Text('Charles端口')
              .fontSize(14)
              .fontColor('#FF515B6C')
              .width('100%')
            TextInput({ placeholder: '8888', text: this.targetPort })
              .type(InputType.Number)
              .height(48)
              .backgroundColor('#FFFFFFFF')
              .onChange((value: string) => {
                this.targetPort = value;
              })

            Text('代理目标应用')
              .fontSize(14)
              .fontColor('#FF515B6C')
              .width('100%')
            Row({ space: 12 }) {
              Column({ space: 4 }) {
                Text(this.targetBundle.length === 0 ? '全部应用' :
                  (this.selectedAppName.length > 0 ? this.selectedAppName : '已指定应用'))
                  .fontSize(17)
                  .fontWeight(FontWeight.Medium)
                Text(this.targetBundle.length === 0 ? '不限制应用范围' : this.targetBundle)
                  .fontSize(12)
                  .fontColor('#FF697386')
              }
              .alignItems(HorizontalAlign.Start)
              .layoutWeight(1)

              Button(this.targetBundle.length === 0 ? '选择应用' : '重新选择')
                .height(40)
                .fontSize(14)
                .enabled(!this.busy && this.status !== 'running')
                .onClick(() => {
                  this.showAppPicker = true;
                })
            }
            .width('100%')
            .padding(12)
            .backgroundColor('#FFFFFFFF')
            .borderRadius(10)
            Text('已内置快手和快手极速版；选择记录会保存在本机')
              .fontSize(12)
              .fontColor('#FF838B98')
              .width('100%')
          }
          .width('100%')

          Button(this.status === 'running' ? '一键关闭代理' :
            (this.busy ? '请稍候…' : '一键启动代理'))
            .width('100%')
            .height(50)
            .fontSize(18)
            .backgroundColor(this.status === 'running' ? '#FFD94B4B' : '#FF246BCE')
            .enabled(!this.busy && !this.initializing)
            .onClick(() => {
              void this.toggleProxy();
            })

          Button('测试连通性')
            .width('100%')
            .height(46)
            .fontSize(16)
            .fontColor('#FF246BCE')
            .backgroundColor('#FFE8F1FF')
            .enabled(!this.busy && !this.initializing && this.status !== 'running')
            .onClick(() => {
              void this.testConnectivity();
            })

          if (this.lastError.length > 0) {
            Text(this.lastError)
              .fontSize(12)
              .fontColor('#FFB23B3B')
              .width('100%')
          }

          Row() {
            Text('历史记录（最多10条）')
              .fontSize(18)
              .fontWeight(FontWeight.Medium)
              .layoutWeight(1)
            Button('清空全部历史')
              .fontSize(13)
              .height(34)
              .fontColor('#FFBD3F45')
              .backgroundColor('#FFFFEEEE')
              .enabled(this.records.length > 0)
              .onClick(() => {
                this.confirmClearHistory();
              })
          }
          .width('100%')

          if (this.records.length === 0) {
            Text('暂无记录。代理启动成功后自动保存，新记录置顶并自动去重。')
              .fontSize(13)
              .fontColor('#FF838B98')
              .width('100%')
              .padding(12)
          } else {
            List({ space: 10 }) {
              ForEach(this.records, (record: ProxyRecord) => {
                ListItem() {
                  this.historyRow(record)
                }
              }, (record: ProxyRecord) => `${record.ip}:${record.port}`)
            }
            .width('100%')
            .height(Math.min(this.records.length, 4) * 78)
            .scrollBar(BarState.Auto)
          }

          Text('说明：Wi-Fi代理必须保持为空。本应用通过VPN TUN转发，不修改系统代理。只抓明文HTTP；HTTPS、SSL Pinning、UDP和QUIC不在处理范围内。')
            .fontSize(12)
            .fontColor('#FF747D8B')
            .lineHeight(20)
            .width('100%')
            .padding({ bottom: 24 })
        }
        .width('100%')
        .padding(20)
      }
      .width('100%')
      .layoutWeight(1)
      .scrollBar(BarState.Auto)
    }
    .width('100%')
    .height('100%')
    .backgroundColor('#FFF4F6FA')
    .bindSheet(this.showAppPicker, this.appPickerSheet(), {
      height: SheetSize.LARGE,
      showClose: true
    })
  }
}
