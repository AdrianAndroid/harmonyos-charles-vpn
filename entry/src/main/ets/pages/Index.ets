import { common, Want } from '@kit.AbilityKit';
import { util } from '@kit.ArkTS';
import { preferences } from '@kit.ArkData';
import { socket, vpnExtension } from '@kit.NetworkKit';
import { BusinessError, commonEventManager } from '@kit.BasicServicesKit';
import {
  BUNDLE_NAME,
  EVENT_ERROR,
  EVENT_READY,
  EVENT_STOPPED,
  EVENT_TRAFFIC,
  VPN_ABILITY_NAME,
  VPN_EVENT
} from '../common/VpnEvents';
import { PipFlowRow, PipParams, TrafficPip } from '../common/TrafficPip';

interface ProxyRecord {
  ip: string;
  port: number;
}

interface CommonAppRecord {
  name: string;
  bundleName: string;
  builtIn: boolean;
}

@Observed
class TrafficEntry {
  flowId: string = '';
  src: string = '';
  dst: string = '';
  method: string = 'TCP';
  host: string = '';
  target: string = '';
  statusLine: string = '';
  statusCode: string = '';
  requestHeaders: string = '';
  responseHeaders: string = '';
  bodyPreview: string = '';
  contentLength: number = 0;
  requestBytes: number = 0;
  responseBytes: number = 0;
  durationMs: number = 0;
  startedAt: number = 0;
  active: boolean = true;
}

const MAX_TRAFFIC_RECORDS: number = 500;

// LazyForEach 数据源：新增只回调 onDataAdd(0)，行内更新直接改 @Observed 对象属性，
// 单行重渲染，避免整表重建。
class TrafficDataSource implements IDataSource {
  private items: TrafficEntry[] = [];
  private indexByFlow: Map<string, number> = new Map();
  private listeners: DataChangeListener[] = [];

  totalCount(): number {
    return this.items.length;
  }

  getData(index: number): TrafficEntry {
    return this.items[index];
  }

  registerDataChangeListener(listener: DataChangeListener): void {
    this.listeners.push(listener);
  }

  unregisterDataChangeListener(listener: DataChangeListener): void {
    const index: number = this.listeners.indexOf(listener);
    if (index >= 0) {
      this.listeners.splice(index, 1);
    }
  }

  count(): number {
    return this.items.length;
  }

  get(flowId: string): TrafficEntry | undefined {
    const index: number | undefined = this.indexByFlow.get(flowId);
    return index === undefined ? undefined : this.items[index];
  }

  clear(): void {
    this.items.splice(0);
    this.indexByFlow.clear();
    for (const listener of this.listeners) {
      listener.onDataReloaded();
    }
  }

  markAllClosed(): void {
    for (const item of this.items) {
      item.active = false;
    }
  }

  add(entry: TrafficEntry): void {
    if (this.items.length + 1 > MAX_TRAFFIC_RECORDS) {
      let drop: number = this.items.length - 1;
      // 优先淘汰最旧的纯 TCP 记录，避免 HTTPS 噪声挤掉已解析的 HTTP 记录。
      for (let i = this.items.length - 1; i > 0; i--) {
        if (this.items[i].method === 'TCP' && !this.items[i].active) {
          drop = i;
          break;
        }
      }
      const removed = this.items.splice(drop, 1)[0];
      this.indexByFlow.delete(removed.flowId);
      // 先按旧列表下标删除，再插入新条目，两次回调的 index 语义才一致。
      for (const listener of this.listeners) {
        listener.onDataDelete(drop);
      }
    }
    this.items.unshift(entry);
    this.rebuildIndex();
    for (const listener of this.listeners) {
      listener.onDataAdd(0);
    }
  }

  private rebuildIndex(): void {
    this.indexByFlow.clear();
    for (let i = 0; i < this.items.length; i++) {
      this.indexByFlow.set(this.items[i].flowId, i);
    }
  }
}

@Component
struct TrafficRow {
  @ObjectLink entry: TrafficEntry;
  @State private expanded: boolean = false;

  build() {
    Column({ space: 8 }) {
      Row({ space: 8 }) {
        Text(this.entry.method)
          .fontSize(10)
          .fontWeight(FontWeight.Bold)
          .fontColor(COLOR_BLUE)
          .padding({ left: 7, right: 7, top: 3, bottom: 3 })
          .backgroundColor('#FFEDF4FF')
          .borderRadius(6)
        Text(this.entry.host.length > 0 ? this.entry.host : this.entry.dst)
          .fontSize(14)
          .fontWeight(FontWeight.Medium)
          .fontColor(COLOR_TEXT)
          .layoutWeight(1)
          .maxLines(1)
          .textOverflow({ overflow: TextOverflow.Ellipsis })
        Circle()
          .width(7)
          .height(7)
          .fill(this.entry.active ? COLOR_GREEN : COLOR_FAINT)
      }
      .width('100%')

      Text(this.entry.target.length > 0 ? this.entry.target : '等待 HTTP 请求…')
        .fontSize(12)
        .fontColor(COLOR_SUB)
        .width('100%')
        .maxLines(1)
        .textOverflow({ overflow: TextOverflow.Ellipsis })

      Row({ space: 8 }) {
        Text(this.entry.statusCode.length > 0 ? this.entry.statusCode : '等待响应')
          .fontSize(12)
          .fontColor(this.entry.statusCode.length > 0 ? statusTone(this.entry.statusCode) : COLOR_FAINT)
        Text(formatBytes(this.entry.contentLength > 0 ? this.entry.contentLength : this.entry.responseBytes))
          .fontSize(11)
          .fontColor(COLOR_FAINT)
        Text(this.entry.durationMs > 0 ? `${this.entry.durationMs} ms` : '—')
          .fontSize(11)
          .fontColor(COLOR_FAINT)
        Blank()
        if (this.entry.method !== 'TCP') {
          Text(this.expanded ? '收起' : '详情')
            .fontSize(12)
            .fontColor(COLOR_BLUE)
        }
      }
      .width('100%')

      if (this.expanded) {
        Column({ space: 6 }) {
          Text('请求头')
            .fontSize(10)
            .fontColor(COLOR_FAINT)
            .width('100%')
          Text(this.entry.requestHeaders.length > 0 ? this.entry.requestHeaders : '（尚未解析到请求头）')
            .fontSize(10)
            .lineHeight(14)
            .fontColor('#FF3C3C43')
            .width('100%')
            .maxLines(12)
            .textOverflow({ overflow: TextOverflow.Ellipsis })
          Text('响应头')
            .fontSize(10)
            .fontColor(COLOR_FAINT)
            .width('100%')
          Text(this.entry.responseHeaders.length > 0 ? this.entry.responseHeaders : '（尚未收到响应）')
            .fontSize(10)
            .lineHeight(14)
            .fontColor('#FF3C3C43')
            .width('100%')
            .maxLines(12)
            .textOverflow({ overflow: TextOverflow.Ellipsis })
          Text('响应体（前 1KB）')
            .fontSize(10)
            .fontColor(COLOR_FAINT)
            .width('100%')
          Text(this.entry.bodyPreview.length > 0 ? this.entry.bodyPreview : '（空、未完成或二进制内容）')
            .fontSize(10)
            .lineHeight(14)
            .fontColor('#FF3C3C43')
            .width('100%')
            .maxLines(12)
            .textOverflow({ overflow: TextOverflow.Ellipsis })
          Text(`${this.entry.src} → ${this.entry.dst}`)
            .fontSize(10)
            .fontColor(COLOR_FAINT)
            .width('100%')
        }
        .width('100%')
        .padding(10)
        .backgroundColor('#FFF7F7FA')
        .borderRadius(10)
      }
    }
    .width('100%')
    .padding(14)
    .backgroundColor(COLOR_CARD)
    .borderRadius(18)
    .onClick(() => {
      this.expanded = !this.expanded;
    })
  }
}

type ProxyStatus = 'stopped' | 'checking' | 'starting' | 'running' | 'stopping';

const HISTORY_KEY: string = 'records';
const COMMON_APPS_KEY: string = 'common_apps';
const SELECTED_APP_BUNDLE_KEY: string = 'selected_app_bundle';
const SELECTED_APP_NAME_KEY: string = 'selected_app_name';
const AUTO_SAVE_KEY: string = 'auto_save_records';
const DEFAULT_COMMON_APPS: CommonAppRecord[] = [
  { name: '快手', bundleName: 'com.kuaishou.hmapp', builtIn: true },
  { name: '快手极速版', bundleName: 'com.kuaishou.hmnebula', builtIn: true }
];
const CONNECT_ERROR: string = '无法连接Charles，检查Charles是否开启、局域网、Access Control、防火墙放行8888端口';

const COLOR_BG: string = '#FFF2F2F7';
const COLOR_CARD: string = '#FFFFFFFF';
const COLOR_TEXT: string = '#FF0A0A0A';
const COLOR_SUB: string = '#FF8E8E93';
const COLOR_FAINT: string = '#FFAEAEB2';
const COLOR_BLUE: string = '#FF0A84FF';
const COLOR_GREEN: string = '#FF34C759';
const COLOR_GRAY: string = '#FF8E8E93';
const COLOR_RED: string = '#FFFF3B30';
const COLOR_PILL: string = '#FFE5E5EA';
const COLOR_SEPARATOR: string = '#FFF1F1F3';
const TAB_LABELS: string[] = ['总览', '流量', '连接', '设置'];

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

function pad2(value: number): string {
  return value < 10 ? `0${value}` : String(value);
}

function formatBytes(value: number): string {
  if (value < 1024) {
    return `${value} B`;
  }
  if (value < 1024 * 1024) {
    return `${(value / 1024).toFixed(1)} KB`;
  }
  return `${(value / (1024 * 1024)).toFixed(1)} MB`;
}

function decodeBase64(value: string): string {
  if (value.length === 0) {
    return '';
  }
  try {
    const bytes: Uint8Array = new util.Base64Helper().decodeSync(value);
    return new util.TextDecoder('utf-8', { fatal: false, ignoreBOM: true }).decodeToString(bytes);
  } catch (error) {
    return '';
  }
}

function statusTone(code: string): string {
  if (code.startsWith('2')) {
    return '#FF16865C';
  }
  if (code.startsWith('3')) {
    return '#FF246BCE';
  }
  if (code.startsWith('4')) {
    return '#FFB26A00';
  }
  if (code.startsWith('5')) {
    return '#FFD53333';
  }
  return '#FF8E8E93';
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
  @State private showTargetSheet: boolean = false;
  @State private showLogs: boolean = false;
  @State private appSearch: string = '';
  @State private newAppName: string = '';
  @State private newAppBundle: string = '';
  @State private status: ProxyStatus = 'stopped';
  @State private records: ProxyRecord[] = [];
  @State private busy: boolean = false;
  @State private initializing: boolean = true;
  @State private lastError: string = '';
  @State private currentTab: number = 0;
  @State private autoSave: boolean = true;
  @State private probeState: string = '未检测';
  @State private logs: string[] = [];
  @State private flowCount: number = 0;
  @State private activeFlows: number = 0;
  @State private downTotal: number = 0;
  @State private upTotal: number = 0;
  @State private busiestLabel: string = '';
  @State private pipOn: boolean = false;
  private trafficStore: TrafficDataSource = new TrafficDataSource();
  private pip: TrafficPip = TrafficPip.shared();
  private pipTimer?: number;
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
  private chartCtx: CanvasRenderingContext2D = new CanvasRenderingContext2D(new RenderingContextSettings(true));

  aboutToAppear(): void {
    this.pip.setActiveListener((active: boolean) => {
      this.pipOn = active;
    });
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
    if (this.pipTimer !== undefined) {
      clearTimeout(this.pipTimer);
      this.pipTimer = undefined;
    }
  }

  private appendLog(message: string): void {
    const now = new Date();
    const line: string = `${pad2(now.getHours())}:${pad2(now.getMinutes())}:${pad2(now.getSeconds())}  ${message}`;
    this.logs = [...this.logs, line].slice(-100);
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
      this.autoSave = await this.store.get(AUTO_SAVE_KEY, true) as boolean;

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
      this.appendLog('应用初始化完成');
    } catch (error) {
      this.lastError = `初始化失败：${errorText(error as Object)}`;
      this.appendLog(this.lastError);
      this.toast(this.lastError);
    } finally {
      this.initializing = false;
    }
  }

  private handleTrafficEvent(data: string): void {
    // 高频事件：不做 console 输出，避免日志本身成为瓶颈。
    const parts: string[] = data.split('\t');
    if (parts.length < 4 || parts[0] !== 'trace') {
      return;
    }
    const kind: string = parts[1];
    const flowId: string = parts[2];
    if (kind === 'flow') {
      if (parts.length < 6) {
        return;
      }
      const entry = new TrafficEntry();
      entry.flowId = flowId;
      entry.src = parts[3];
      entry.dst = parts[4];
      entry.startedAt = Number(parts[5]);
      this.trafficStore.add(entry);
      this.flowCount = this.trafficStore.count();
      this.activeFlows += 1;
      this.queuePipUpdate();
      return;
    }
    const entry: TrafficEntry | undefined = this.trafficStore.get(flowId);
    if (entry === undefined) {
      return;
    }
    if (kind === 'req' && parts.length >= 8) {
      entry.method = parts[3];
      entry.host = parts[4];
      entry.target = parts[5];
      entry.requestHeaders = decodeBase64(parts[6]);
      entry.startedAt = Number(parts[7]);
      // 同一 keep-alive 连接上的新请求：先清掉上一笔的响应，避免展示旧值。
      entry.statusLine = '';
      entry.statusCode = '';
      entry.responseHeaders = '';
      entry.bodyPreview = '';
      entry.contentLength = 0;
      entry.responseBytes = 0;
      entry.durationMs = 0;
      entry.active = true;
      this.busiestLabel = `${entry.method}  ${entry.host}${entry.target}`;
    } else if (kind === 'resp' && parts.length >= 8) {
      // trace resp <flowId> <respIndex> <statusB64> <headerB64> <contentLength> <ts>
      entry.statusLine = decodeBase64(parts[4]);
      const tokens: string[] = entry.statusLine.split(' ');
      entry.statusCode = tokens.length >= 2 ? tokens[1] : '';
      entry.responseHeaders = decodeBase64(parts[5]);
      entry.contentLength = Number(parts[6]);
    } else if (kind === 'body' && parts.length >= 7) {
      // trace body <flowId> <respIndex> <previewB64> <bodyBytes> <durationMs>
      entry.bodyPreview = decodeBase64(parts[4]);
      entry.responseBytes = Number(parts[5]);
      entry.durationMs = Number(parts[6]);
    } else if (kind === 'close' && parts.length >= 6) {
      entry.requestBytes = Number(parts[3]);
      entry.responseBytes = Number(parts[4]);
      entry.durationMs = Number(parts[5]);
      entry.active = false;
      this.upTotal += entry.requestBytes;
      this.downTotal += entry.responseBytes;
      if (this.activeFlows > 0) {
        this.activeFlows -= 1;
      }
    } else {
      return;
    }
    // entry 是 @Observed 对象，属性变更只会让对应 TrafficRow 重渲染。
    this.queuePipUpdate();
  }

  private pipSnapshot(): PipParams {
    const params = new PipParams();
    params.running = this.status === 'running';
    params.total = this.flowCount;
    params.active = this.activeFlows;
    params.downText = formatBytes(this.downTotal);
    params.upText = formatBytes(this.upTotal);
    const rows: PipFlowRow[] = [];
    for (let i = 0; i < this.trafficStore.count() && rows.length < 6; i++) {
      const item: TrafficEntry = this.trafficStore.getData(i);
      const row = new PipFlowRow();
      row.method = item.method;
      row.host = item.host.length > 0 ? item.host : item.dst;
      row.path = item.target;
      row.statusCode = item.statusCode;
      row.sizeText = formatBytes(item.contentLength > 0 ? item.contentLength : item.responseBytes);
      row.active = item.active;
      rows.push(row);
    }
    params.rows = rows;
    return params;
  }

  private queuePipUpdate(): void {
    if (!this.pip.isActive()) {
      return;
    }
    if (this.pipTimer !== undefined) {
      return;
    }
    this.pipTimer = setTimeout(() => {
      this.pipTimer = undefined;
      this.pip.update(this.pipSnapshot());
    }, 400);
  }

  private async togglePip(): Promise<void> {
    if (this.pip.isActive()) {
      await this.pip.stop();
      return;
    }
    try {
      const host = this.getUIContext().getHostContext() as common.UIAbilityContext;
      await this.pip.start(host, this.getUIContext(), this.pipSnapshot());
    } catch (error) {
      this.toast(`悬浮窗启动失败：${errorText(error as Object)}`);
    }
  }

  private clearTraffic(): void {
    this.trafficStore.clear();
    this.flowCount = 0;
    this.activeFlows = 0;
    this.upTotal = 0;
    this.downTotal = 0;
    this.busiestLabel = '';
    this.queuePipUpdate();
  }

  private busiestText(): string {
    if (this.status !== 'running') {
      return '代理未运行。';
    }
    return this.busiestLabel.length > 0 ? this.busiestLabel : '当前没有流量。';
  }

  private async handleVpnEvent(event: commonEventManager.CommonEventData): Promise<void> {
    if (event.event !== VPN_EVENT) {
      return;
    }
    if (event.code === EVENT_TRAFFIC) {
      this.handleTrafficEvent(event.data ?? '');
      return;
    }
    if (event.code === EVENT_READY) {
      this.status = 'running';
      this.activeBundle = this.startingBundle;
      this.busy = false;
      this.lastError = '';
      this.probeState = '可达';
      const resolve = this.readyResolve;
      this.clearPendingStart();
      resolve?.();
      await this.rememberCurrentTarget();
      this.appendLog(`代理已启动 ${this.targetIp}:${this.targetPort}`);
      this.toast('✅ 代理已启动，状态栏出现VPN图标');
      return;
    }
    if (event.code === EVENT_STOPPED) {
      const wasStopping: boolean = this.stopRequested || this.status === 'stopping';
      const wasRunning: boolean = this.status === 'running';
      this.status = 'stopped';
      this.activeBundle = '';
      this.busy = false;
      this.probeState = '未检测';
      this.trafficStore.markAllClosed();
      this.activeFlows = 0;
      this.queuePipUpdate();
      const resolve = this.stoppedResolve;
      this.stoppedResolve = undefined;
      resolve?.();
      this.stopRequested = false;
      this.appendLog('代理已停止');
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
      this.appendLog(`转发错误：${message}`);
      this.toast(`转发错误：${message}`);

      // 单条 Charles 连接失败不等于 VPN 已停止；保持运行状态并允许后续流重试。
      if (!fatal && (this.status === 'running' || this.status === 'stopping')) {
        return;
      }
      this.status = 'stopped';
      this.activeBundle = '';
      this.busy = false;
      this.stopRequested = false;
      this.probeState = '未检测';
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
    this.probeState = '检测中';
    const reachable: boolean = await this.probeCharles();
    this.busy = false;
    this.status = 'stopped';
    if (reachable) {
      this.probeState = '可达';
      this.appendLog(`探测成功 ${this.targetIp}:${this.targetPort}`);
      this.toast(`✅ 已连接Charles ${this.targetIp}:${this.targetPort}`);
    } else {
      this.probeState = '不可达';
      this.appendLog(`探测失败 ${this.targetIp}:${this.targetPort}：${this.lastError}`);
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
    this.appendLog(`启动代理 ${this.targetIp}:${this.targetPort}`);

    // 必须先探测，失败则不调用 VPN 启动接口，也不会弹系统授权框。
    if (!await this.probeCharles()) {
      this.busy = false;
      this.status = 'stopped';
      this.startingRecord = undefined;
      this.startingBundle = '';
      this.probeState = '不可达';
      this.appendLog(`启动前探测失败：${this.lastError}`);
      this.showConnectFailure();
      return;
    }

    this.probeState = '可达';
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
      this.probeState = '不可达';
      this.appendLog(`启动代理失败：${message}`);
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
    this.appendLog('正在关闭代理');
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
        this.probeState = '未检测';
        this.appendLog('代理已关闭');
        this.toast('✅ 代理已关闭');
      } else {
        await stopped;
      }
    } catch (error) {
      this.stopRequested = false;
      this.stoppedResolve = undefined;
      this.lastError = errorText(error as Object);
      this.appendLog(`关闭代理失败：${this.lastError}`);
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

  private async reconnect(): Promise<void> {
    if (this.busy || this.initializing) {
      return;
    }
    this.appendLog('重新连接');
    if (this.status === 'running') {
      await this.stopProxy();
      if (this.status === 'running') {
        return;
      }
    }
    await this.startProxy();
  }

  private openAppPicker(): void {
    if (this.busy || this.status === 'running') {
      this.toast('请先关闭代理再修改应用范围');
      return;
    }
    this.showAppPicker = true;
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

  private async persistAutoSave(): Promise<void> {
    if (!this.store) {
      return;
    }
    try {
      await this.store.put(AUTO_SAVE_KEY, this.autoSave);
      await this.store.flush();
    } catch (error) {
      this.toast(`设置保存失败：${errorText(error as Object)}`);
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
    if (!this.autoSave) {
      return;
    }
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
      this.toast('暂无可清空的历史记录');
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
          this.appendLog('已清空全部历史记录');
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

  private statusShort(): string {
    switch (this.status) {
      case 'running':
        return '已连接';
      case 'checking':
        return '检测中';
      case 'starting':
        return '启动中';
      case 'stopping':
        return '关闭中';
      default:
        return '未连接';
    }
  }

  private statusColor(): string {
    switch (this.status) {
      case 'running':
        return COLOR_GREEN;
      case 'checking':
      case 'starting':
      case 'stopping':
        return COLOR_BLUE;
      default:
        return COLOR_GRAY;
    }
  }

  private modeLabel(): string {
    return this.targetBundle.length === 0 ? '全局' : '规则';
  }

  private scopeLabel(): string {
    if (this.targetBundle.length === 0) {
      return '全部应用';
    }
    return this.selectedAppName.length > 0 ? this.selectedAppName : this.targetBundle;
  }

  private targetLabel(): string {
    if (!isValidIpv4(this.targetIp)) {
      return '未配置 Charles';
    }
    return `${this.targetIp}:${this.targetPort}`;
  }

  private drawTrafficChart(): void {
    const ctx = this.chartCtx;
    const width: number = ctx.width;
    const height: number = ctx.height;
    if (width <= 0 || height <= 0) {
      return;
    }
    ctx.clearRect(0, 0, width, height);
    ctx.strokeStyle = this.status === 'running' ? COLOR_GREEN : '#FFE5E5EA';
    ctx.lineWidth = 2;
    ctx.beginPath();
    ctx.moveTo(0, height - 1);
    ctx.lineTo(width, height - 1);
    ctx.stroke();
  }

  private subtitleText(variant: number): string {
    if (variant === 0) {
      return `${this.statusText()} · ${this.modeLabel()}`;
    }
    if (variant === 1) {
      return `${this.statusShort()} · ${this.modeLabel()}`;
    }
    if (variant === 2) {
      return `${this.statusText()} · ${this.scopeLabel()}`;
    }
    return 'Charles 局域网抓包代理';
  }

  @Builder
  private titleBlock(title: string, variant: number) {
    Column({ space: 8 }) {
      Text(title)
        .fontSize(34)
        .fontWeight(FontWeight.Bold)
        .fontColor(COLOR_TEXT)
        .width('100%')
      Row({ space: 8 }) {
        Circle()
          .width(8)
          .height(8)
          .fill(this.statusColor())
        Text(this.subtitleText(variant))
          .fontSize(14)
          .fontColor(COLOR_SUB)
      }
      .width('100%')
    }
    .width('100%')
    .alignItems(HorizontalAlign.Start)
  }

  @Builder
  private sectionLabel(text: string) {
    Text(text)
      .fontSize(13)
      .fontColor(COLOR_FAINT)
      .width('100%')
  }

  private statValue(kind: number): string {
    if (kind === 0) {
      return formatBytes(this.downTotal);
    }
    if (kind === 1) {
      return formatBytes(this.upTotal);
    }
    return String(this.activeFlows);
  }

  @Builder
  private statCell(label: string, kind: number) {
    Column({ space: 4 }) {
      Text(label)
        .fontSize(12)
        .fontColor(COLOR_SUB)
      Text(this.statValue(kind))
        .fontSize(21)
        .fontWeight(FontWeight.Medium)
        .fontColor(COLOR_TEXT)
    }
    .layoutWeight(1)
    .alignItems(HorizontalAlign.Start)
  }

  private infoValue(kind: number): string {
    return kind === 0 ? this.scopeLabel() : 'TUN · IPv4';
  }

  @Builder
  private infoCard(label: string, kind: number) {
    Column({ space: 8 }) {
      Text(label)
        .fontSize(12)
        .fontColor(COLOR_FAINT)
      Text(this.infoValue(kind))
        .fontSize(20)
        .fontWeight(FontWeight.Medium)
        .fontColor(COLOR_TEXT)
        .maxLines(2)
        .textOverflow({ overflow: TextOverflow.Ellipsis })
    }
    .layoutWeight(1)
    .alignItems(HorizontalAlign.Start)
    .padding(16)
    .height(84)
    .backgroundColor(COLOR_CARD)
    .borderRadius(20)
  }

  @Builder
  private trafficCard() {
    Column() {
      Row() {
        Column({ space: 6 }) {
          Text('下载')
            .fontSize(13)
            .fontColor(COLOR_BLUE)
          Row({ space: 4 }) {
            Text('0')
              .fontSize(42)
              .fontWeight(FontWeight.Bold)
              .fontColor(COLOR_TEXT)
            Text('B/s')
              .fontSize(14)
              .fontColor(COLOR_SUB)
              .margin({ bottom: 8 })
          }
          .alignItems(VerticalAlign.Bottom)
        }
        .alignItems(HorizontalAlign.Start)
        .layoutWeight(1)

        Column({ space: 6 }) {
          Text('上传')
            .fontSize(13)
            .fontColor(COLOR_GREEN)
          Row({ space: 4 }) {
            Text('0')
              .fontSize(42)
              .fontWeight(FontWeight.Bold)
              .fontColor(COLOR_TEXT)
            Text('B/s')
              .fontSize(14)
              .fontColor(COLOR_SUB)
              .margin({ bottom: 8 })
          }
          .alignItems(VerticalAlign.Bottom)
        }
        .alignItems(HorizontalAlign.End)
        .layoutWeight(1)
      }
      .width('100%')
      .padding({ left: 20, right: 20, top: 20, bottom: 8 })

      Canvas(this.chartCtx)
        .width('100%')
        .height(112)
        .onReady(() => {
          this.drawTrafficChart();
        })

      Divider()
        .color(COLOR_SEPARATOR)
        .margin({ top: 4 })

      Row() {
        this.statCell('已接收', 0)
        this.statCell('已发送', 1)
        this.statCell('活动连接', 2)
      }
      .width('100%')
      .padding({ left: 20, right: 20, top: 16, bottom: 18 })
    }
    .width('100%')
    .backgroundColor(COLOR_CARD)
    .borderRadius(24)
  }

  @Builder
  private historyRow(record: ProxyRecord) {
    Row() {
      Column({ space: 4 }) {
        Text(`${record.ip}:${record.port}`)
          .fontSize(17)
          .fontWeight(FontWeight.Medium)
          .fontColor(COLOR_TEXT)
        Text('点击填充 · 长按删除')
          .fontSize(12)
          .fontColor(COLOR_FAINT)
      }
      .alignItems(HorizontalAlign.Start)
      .layoutWeight(1)

      Text('使用')
        .fontSize(14)
        .fontColor(COLOR_BLUE)
    }
    .width('100%')
    .padding({ left: 18, right: 18, top: 14, bottom: 14 })
    .backgroundColor(COLOR_CARD)
    .borderRadius(18)
    .onClick(() => {
      this.targetIp = record.ip;
      this.targetPort = String(record.port);
    })
    .gesture(LongPressGesture().onAction(() => {
      this.deleteRecord(record);
    }))
  }

  @Builder
  private tabIcon(index: number, color: string) {
    if (index === 0) {
      Row({ space: 2 }) {
        Rect().width(4).height(11).radius(2).fill(color)
        Rect().width(4).height(18).radius(2).fill(color)
        Rect().width(4).height(24).radius(2).fill(color)
      }
      .height(24)
      .alignItems(VerticalAlign.Bottom)
    } else if (index === 1) {
      Column({ space: 3 }) {
        Row({ space: 5 }) {
          Circle().width(7).height(7).fill(color)
          Circle().width(7).height(7).fill(color)
        }
        Circle().width(7).height(7).fill(color)
      }
      .height(24)
      .justifyContent(FlexAlign.Center)
    } else if (index === 2) {
      Text('⇅')
        .fontSize(23)
        .fontColor(color)
        .height(24)
    } else {
      Column({ space: 3 }) {
        Row({ space: 2 }) {
          Rect().width(7).height(2).radius(1).fill(color)
          Circle().width(5).height(5).fill(color)
          Rect().width(8).height(2).radius(1).fill(color)
        }
        Row({ space: 2 }) {
          Rect().width(9).height(2).radius(1).fill(color)
          Circle().width(5).height(5).fill(color)
          Rect().width(6).height(2).radius(1).fill(color)
        }
        Row({ space: 2 }) {
          Rect().width(6).height(2).radius(1).fill(color)
          Circle().width(5).height(5).fill(color)
          Rect().width(9).height(2).radius(1).fill(color)
        }
      }
      .width(24)
      .height(24)
      .justifyContent(FlexAlign.Center)
    }
  }

  @Builder
  private tabItem(label: string, index: number) {
    Column({ space: 4 }) {
      this.tabIcon(index, this.currentTab === index ? COLOR_BLUE : '#FF3C3C43')
      Text(label)
        .fontSize(11)
        .fontWeight(this.currentTab === index ? FontWeight.Medium : FontWeight.Regular)
        .fontColor(this.currentTab === index ? COLOR_BLUE : '#FF3C3C43')
    }
    .layoutWeight(1)
    .height(52)
    .justifyContent(FlexAlign.Center)
    .backgroundColor(this.currentTab === index ? COLOR_PILL : '#00000000')
    .borderRadius(18)
    .onClick(() => {
      this.currentTab = index;
    })
  }

  @Builder
  private bottomBar() {
    Column({ space: 10 }) {
      Row({ space: 12 }) {
        Text('◎')
          .fontSize(24)
          .fontColor(this.status === 'running' ? COLOR_BLUE : COLOR_SUB)
          .width(28)
        Column({ space: 3 }) {
          Text('CHARLES')
            .fontSize(17)
            .fontWeight(FontWeight.Medium)
            .fontColor(COLOR_TEXT)
          Text(`${this.targetLabel()}   ↓ 0 B/s   ↑ 0 B/s`)
            .fontSize(11)
            .fontColor(COLOR_SUB)
            .maxLines(1)
            .textOverflow({ overflow: TextOverflow.Ellipsis })
        }
        .alignItems(HorizontalAlign.Start)
        .layoutWeight(1)

        Column({ space: 1 }) {
          Text('⌃').fontSize(10).fontColor(COLOR_FAINT)
          Text('⌄').fontSize(10).fontColor(COLOR_FAINT)
        }
        .width(18)
      }
      .width('100%')
      .height(64)
      .padding({ left: 18, right: 14 })
      .backgroundColor(COLOR_CARD)
      .borderRadius(32)
      .shadow({ radius: 18, color: '#12000000', offsetY: 6 })
      .onClick(() => {
        this.currentTab = 3;
      })
      .bindSheet(this.showTargetSheet, this.targetSheet(), {
        height: SheetSize.LARGE,
        showClose: false,
        shouldDismiss: (dismiss: SheetDismiss) => {
          this.showTargetSheet = false;
          dismiss.dismiss();
        }
      })

      Row() {
        ForEach(TAB_LABELS, (label: string, index: number) => {
          this.tabItem(label, index)
        }, (label: string) => label)
      }
      .width('100%')
      .height(68)
      .padding(8)
      .backgroundColor(COLOR_CARD)
      .borderRadius(34)
      .shadow({ radius: 18, color: '#12000000', offsetY: 6 })
      .bindSheet(this.showLogs, this.logSheet(), {
        height: SheetSize.LARGE,
        showClose: false,
        shouldDismiss: (dismiss: SheetDismiss) => {
          this.showLogs = false;
          dismiss.dismiss();
        }
      })
    }
    .width('100%')
    .padding({ left: 16, right: 16, bottom: 6 })
  }

  @Builder
  private overviewPage() {
    Scroll() {
      Column({ space: 16 }) {
        this.titleBlock('总览', 0)

        this.trafficCard()

        this.sectionLabel('当前最繁忙')
        Column() {
          Text(this.busiestText())
            .fontSize(15)
            .fontColor(COLOR_SUB)
            .width('100%')
        }
        .width('100%')
        .padding(18)
        .backgroundColor(COLOR_CARD)
        .borderRadius(20)

        Row({ space: 12 }) {
          this.infoCard('模式', 0)
          this.infoCard('入站', 1)
        }
        .width('100%')

        Text('已接收/已发送与活动连接来自内核实时上报；速率曲线暂未接入。')
          .fontSize(11)
          .fontColor(COLOR_FAINT)
          .lineHeight(18)
          .width('100%')
          .padding({ left: 4, right: 4 })
      }
      .width('100%')
      .padding({ left: 20, right: 20, top: 16, bottom: 24 })
    }
    .width('100%')
    .layoutWeight(1)
    .scrollBar(BarState.Off)
    .align(Alignment.Top)
  }

  @Builder
  private trafficPage() {
    Column() {
      Row({ space: 14 }) {
        Text('流量')
          .fontSize(34)
          .fontWeight(FontWeight.Bold)
          .fontColor(COLOR_TEXT)
          .layoutWeight(1)
        Text(`HTTP ${this.flowCount}`)
          .fontSize(13)
          .fontColor(COLOR_FAINT)
        Text(this.pipOn ? '关闭悬浮' : '悬浮')
          .fontSize(13)
          .fontColor(this.pipOn ? COLOR_RED : COLOR_BLUE)
          .onClick(() => {
            void this.togglePip();
          })
        if (this.flowCount > 0) {
          Text('清空')
            .fontSize(13)
            .fontColor(COLOR_RED)
            .onClick(() => {
              this.clearTraffic();
            })
        }
      }
      .width('100%')
      .padding({ left: 20, right: 20, top: 16, bottom: 12 })

      if (this.flowCount === 0) {
        Column() {
          Text('暂无 HTTP 流量。启动代理并访问明文 HTTP 后，请求/响应会实时显示在这里。')
            .fontSize(13)
            .fontColor(COLOR_SUB)
            .width('100%')
        }
        .width('100%')
        .padding(18)
        .margin({ left: 20, right: 20 })
        .backgroundColor(COLOR_CARD)
        .borderRadius(20)
      } else {
        List({ space: 10 }) {
          LazyForEach(this.trafficStore, (entry: TrafficEntry) => {
            ListItem() {
              TrafficRow({ entry: entry })
            }
          }, (entry: TrafficEntry) => entry.flowId)
        }
        .width('100%')
        .layoutWeight(1)
        .padding({ left: 20, right: 20, bottom: 16 })
        .scrollBar(BarState.Auto)
        .edgeEffect(EdgeEffect.Spring)
        .cachedCount(10)
      }
    }
    .width('100%')
    .layoutWeight(1)
    .alignItems(HorizontalAlign.Start)
  }

  @Builder
  private connectionPage() {
    Scroll() {
      Column({ space: 16 }) {
        this.titleBlock('连接', 2)

        Column() {
          Column({ space: 6 }) {
            Row({ space: 8 }) {
              Circle().width(10).height(10).fill(this.statusColor())
              Text(this.statusShort())
                .fontSize(24)
                .fontWeight(FontWeight.Bold)
                .fontColor(this.status === 'running' ? COLOR_GREEN : COLOR_TEXT)
            }
            Text(this.targetLabel())
              .fontSize(14)
              .fontColor(COLOR_BLUE)
            Text(this.targetBundle.length === 0 ? '代理范围：全部应用' : `代理范围：${this.scopeLabel()}`)
              .fontSize(12)
              .fontColor(COLOR_SUB)
          }
          .alignItems(HorizontalAlign.Start)
          .width('100%')
          .padding({ left: 20, right: 20, top: 20, bottom: 16 })

          Divider().color(COLOR_SEPARATOR)

          Row({ space: 10 }) {
            Button(this.status === 'running' ? '关闭代理' : (this.busy ? '请稍候…' : '启动代理'))
              .layoutWeight(1)
              .height(46)
              .fontSize(16)
              .fontColor('#FFFFFFFF')
              .backgroundColor(this.status === 'running' ? COLOR_RED : COLOR_BLUE)
              .borderRadius(14)
              .enabled(!this.busy && !this.initializing)
              .onClick(() => {
                void this.toggleProxy();
              })
            Button('测试连通性')
              .layoutWeight(1)
              .height(46)
              .fontSize(16)
              .fontColor(COLOR_BLUE)
              .backgroundColor('#FFEDF4FF')
              .borderRadius(14)
              .enabled(!this.busy && !this.initializing && this.status !== 'running')
              .onClick(() => {
                void this.testConnectivity();
              })
          }
          .width('100%')
          .padding(16)

          Divider().color(COLOR_SEPARATOR)

          Row() {
            Text('目标地址')
              .fontSize(14)
              .fontColor(COLOR_SUB)
              .layoutWeight(1)
            Text(this.targetLabel())
              .fontSize(13)
              .fontColor(COLOR_BLUE)
              .margin({ right: 8 })
            Text('编辑')
              .fontSize(13)
              .fontColor(COLOR_BLUE)
          }
          .width('100%')
          .padding({ left: 20, right: 20, top: 14, bottom: 14 })
          .onClick(() => {
            this.showTargetSheet = true;
          })

          Divider().color(COLOR_SEPARATOR).margin({ left: 20 })

          Row() {
            Text('代理应用')
              .fontSize(14)
              .fontColor(COLOR_SUB)
              .layoutWeight(1)
            Text(this.scopeLabel())
              .fontSize(13)
              .fontColor(COLOR_BLUE)
              .margin({ right: 8 })
              .maxLines(1)
              .textOverflow({ overflow: TextOverflow.Ellipsis })
            Text('选择')
              .fontSize(13)
              .fontColor(COLOR_BLUE)
          }
          .width('100%')
          .padding({ left: 20, right: 20, top: 14, bottom: 14 })
          .onClick(() => {
            this.openAppPicker();
          })

          if (this.lastError.length > 0) {
            Text(this.lastError)
              .fontSize(12)
              .fontColor(COLOR_RED)
              .width('100%')
              .padding({ left: 20, right: 20, bottom: 16 })
          }
        }
        .width('100%')
        .backgroundColor(COLOR_CARD)
        .borderRadius(24)

        Row() {
          Text(`连接记录 · ${this.records.length}`)
            .fontSize(13)
            .fontColor(COLOR_FAINT)
            .layoutWeight(1)
          Text('清空')
            .fontSize(13)
            .fontColor(this.records.length > 0 ? COLOR_RED : COLOR_FAINT)
            .onClick(() => {
              this.confirmClearHistory();
            })
        }
        .width('100%')

        if (this.records.length === 0) {
          Column() {
            Text('暂无连接记录。代理启动成功后自动保存。')
              .fontSize(14)
              .fontColor(COLOR_SUB)
              .width('100%')
          }
          .width('100%')
          .padding(18)
          .backgroundColor(COLOR_CARD)
          .borderRadius(20)
        } else {
          List({ space: 10 }) {
            ForEach(this.records, (record: ProxyRecord) => {
              ListItem() {
                this.historyRow(record)
              }
            }, (record: ProxyRecord) => `${record.ip}:${record.port}`)
          }
          .width('100%')
          .height(Math.min(this.records.length, 5) * 74)
          .scrollBar(BarState.Off)
        }

        Text('历史记录保存在本机，最多 10 条；点击记录可填入目标地址。')
          .fontSize(11)
          .fontColor(COLOR_FAINT)
          .lineHeight(18)
          .width('100%')
          .padding({ left: 4, right: 4 })
      }
      .width('100%')
      .padding({ left: 20, right: 20, top: 16, bottom: 24 })
    }
    .width('100%')
    .layoutWeight(1)
    .scrollBar(BarState.Off)
    .align(Alignment.Top)
  }

  @Builder
  private settingsPage() {
    Scroll() {
      Column({ space: 16 }) {
        this.titleBlock('设置', 3)

        Column() {
          Row({ space: 10 }) {
            Column({ space: 6 }) {
              Text('CHARLES')
                .fontSize(21)
                .fontWeight(FontWeight.Bold)
                .fontColor(COLOR_TEXT)
              Text(`http://${this.targetLabel()}`)
                .fontSize(13)
                .fontColor(COLOR_SUB)
              Row({ space: 6 }) {
                Circle().width(7).height(7).fill(this.statusColor())
                Text(`${this.statusShort()} · API 26`)
                  .fontSize(12)
                  .fontColor(this.status === 'running' ? COLOR_GREEN : COLOR_SUB)
              }
              Text('点击编辑 IP 与端口')
                .fontSize(11)
                .fontColor(COLOR_BLUE)
            }
            .alignItems(HorizontalAlign.Start)
            .layoutWeight(1)

            Text('›')
              .fontSize(26)
              .fontColor(COLOR_FAINT)
          }
          .width('100%')
          .padding(18)
          .onClick(() => {
            this.showTargetSheet = true;
          })

          Divider().color(COLOR_SEPARATOR)

          Row({ space: 8 }) {
            Text('⟳')
              .fontSize(18)
              .fontColor(this.busy ? COLOR_FAINT : COLOR_BLUE)
            Text('重新连接')
              .fontSize(15)
              .fontColor(this.busy ? COLOR_FAINT : COLOR_BLUE)
          }
          .width('100%')
          .height(50)
          .justifyContent(FlexAlign.Center)
          .onClick(() => {
            void this.reconnect();
          })
        }
        .width('100%')
        .backgroundColor(COLOR_CARD)
        .borderRadius(24)

        Row({ space: 12 }) {
          Column({ space: 8 }) {
            Row() {
              Text('☰')
                .fontSize(20)
                .fontColor(COLOR_BLUE)
                .layoutWeight(1)
              Text('›')
                .fontSize(20)
                .fontColor(COLOR_FAINT)
            }
            .width('100%')
            Text('规则')
              .fontSize(17)
              .fontWeight(FontWeight.Medium)
              .fontColor(COLOR_TEXT)
              .width('100%')
            Text(this.targetBundle.length === 0 ? '全部应用 · 点击选择' : `${this.scopeLabel()} · 点击选择`)
              .fontSize(12)
              .fontColor(COLOR_SUB)
              .width('100%')
              .maxLines(1)
              .textOverflow({ overflow: TextOverflow.Ellipsis })
          }
          .layoutWeight(1)
          .alignItems(HorizontalAlign.Start)
          .padding(16)
          .height(122)
          .backgroundColor(COLOR_CARD)
          .borderRadius(22)
          .onClick(() => {
            this.openAppPicker();
          })

          Column({ space: 8 }) {
            Row() {
              Text('▤')
                .fontSize(18)
                .fontColor(COLOR_BLUE)
                .layoutWeight(1)
              Text('›')
                .fontSize(20)
                .fontColor(COLOR_FAINT)
            }
            .width('100%')
            Text('日志')
              .fontSize(17)
              .fontWeight(FontWeight.Medium)
              .fontColor(COLOR_TEXT)
              .width('100%')
            Text('内核实时输出')
              .fontSize(12)
              .fontColor(COLOR_SUB)
              .width('100%')
          }
          .layoutWeight(1)
          .alignItems(HorizontalAlign.Start)
          .padding(16)
          .height(122)
          .backgroundColor(COLOR_CARD)
          .borderRadius(22)
          .onClick(() => {
            this.showLogs = true;
          })
        }
        .width('100%')

        Row({ space: 10 }) {
          Text('◈')
            .fontSize(22)
            .fontColor(COLOR_BLUE)
          Text('仅明文 HTTP')
            .fontSize(16)
            .fontWeight(FontWeight.Medium)
            .fontColor(COLOR_TEXT)
            .layoutWeight(1)
          Text('调试版')
            .fontSize(13)
            .fontColor(COLOR_SUB)
          Text('›')
            .fontSize(20)
            .fontColor(COLOR_FAINT)
        }
        .width('100%')
        .height(68)
        .padding({ left: 18, right: 16 })
        .backgroundColor(COLOR_CARD)
        .borderRadius(22)

        this.sectionLabel('内核')

        Column() {
          Row() {
            Column({ space: 4 }) {
              Text('单应用模式')
                .fontSize(16)
                .fontColor(COLOR_TEXT)
              Text('仅代理选定应用；关闭后代理全部应用')
                .fontSize(12)
                .fontColor(COLOR_SUB)
            }
            .alignItems(HorizontalAlign.Start)
            .layoutWeight(1)
            Toggle({ type: ToggleType.Switch, isOn: this.targetBundle.length > 0 })
              .selectedColor(COLOR_GREEN)
              .enabled(!this.busy && this.status !== 'running')
              .onChange((isOn: boolean) => {
                if (isOn) {
                  this.openAppPicker();
                } else {
                  void this.selectAllApps();
                }
              })
          }
          .width('100%')
          .padding({ left: 18, right: 18, top: 14, bottom: 14 })

          Divider().color(COLOR_SEPARATOR).margin({ left: 18 })

          Row() {
            Column({ space: 4 }) {
              Text('自动保存启动记录')
                .fontSize(16)
                .fontColor(COLOR_TEXT)
              Text('代理启动成功后保存目标地址')
                .fontSize(12)
                .fontColor(COLOR_SUB)
            }
            .alignItems(HorizontalAlign.Start)
            .layoutWeight(1)
            Toggle({ type: ToggleType.Switch, isOn: this.autoSave })
              .selectedColor(COLOR_GREEN)
              .onChange((isOn: boolean) => {
                this.autoSave = isOn;
                void this.persistAutoSave();
              })
          }
          .width('100%')
          .padding({ left: 18, right: 18, top: 14, bottom: 14 })

          Divider().color(COLOR_SEPARATOR).margin({ left: 18 })

          Row() {
            Column({ space: 4 }) {
              Text('IPv6')
                .fontSize(16)
                .fontColor(COLOR_FAINT)
              Text('当前内核仅处理 IPv4')
                .fontSize(12)
                .fontColor(COLOR_FAINT)
            }
            .alignItems(HorizontalAlign.Start)
            .layoutWeight(1)
            Toggle({ type: ToggleType.Switch, isOn: false })
              .enabled(false)
          }
          .width('100%')
          .padding({ left: 18, right: 18, top: 14, bottom: 14 })

          Divider().color(COLOR_SEPARATOR).margin({ left: 18 })

          Row() {
            Column({ space: 1 }) {
              Rect().width(7).height(2).radius(1).fill(COLOR_RED)
              Rect().width(14).height(2).radius(1).fill(COLOR_RED)
              Rect()
                .width(11)
                .height(11)
                .radius(1)
                .fill('#00000000')
                .stroke(COLOR_RED)
                .strokeWidth(1.5)
            }
            .width(18)
            .height(18)
            .margin({ right: 10 })
            Text('清空历史记录')
              .fontSize(16)
              .fontColor(COLOR_RED)
              .layoutWeight(1)
            Text(`${this.records.length}`)
              .fontSize(14)
              .fontColor(COLOR_FAINT)
          }
          .width('100%')
          .padding({ left: 18, right: 18, top: 16, bottom: 16 })
          .onClick(() => {
            this.confirmClearHistory();
          })
        }
        .width('100%')
        .backgroundColor(COLOR_CARD)
        .borderRadius(22)

        Text('说明：Wi-Fi代理必须保持为空。本应用通过VPN TUN转发，不修改系统代理。只抓明文HTTP；HTTPS、SSL Pinning、UDP和QUIC不在处理范围内。')
          .fontSize(11)
          .fontColor(COLOR_FAINT)
          .lineHeight(18)
          .width('100%')
          .padding({ left: 4, right: 4 })
      }
      .width('100%')
      .padding({ left: 20, right: 20, top: 16, bottom: 24 })
    }
    .width('100%')
    .layoutWeight(1)
    .scrollBar(BarState.Off)
    .align(Alignment.Top)
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
          .backgroundColor(COLOR_BLUE)
          .onClick(() => {
            this.showAppPicker = false;
          })
      }
      .width('100%')

      TextInput({ placeholder: '搜索应用名称或Bundle', text: this.appSearch })
        .type(InputType.Normal)
        .height(44)
        .backgroundColor(COLOR_CARD)
        .borderRadius(12)
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
            .fontColor(COLOR_SUB)
        }
        .alignItems(HorizontalAlign.Start)
        .layoutWeight(1)
        Text(this.targetBundle.length === 0 ? '当前选择' : '选择')
          .fontSize(14)
          .fontColor(COLOR_BLUE)
      }
      .width('100%')
      .padding(14)
      .backgroundColor(this.targetBundle.length === 0 ? '#FFE8F1FF' : COLOR_CARD)
      .borderRadius(14)
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
                  .fontColor(COLOR_SUB)
              }
              .alignItems(HorizontalAlign.Start)
              .layoutWeight(1)

              Text(app.builtIn ? '内置' : '长按删除')
                .fontSize(12)
                .fontColor(COLOR_FAINT)
              Text(this.targetBundle === app.bundleName ? '当前选择' : '选择')
                .fontSize(14)
                .fontColor(COLOR_BLUE)
                .margin({ left: 12 })
            }
            .width('100%')
            .padding(14)
            .backgroundColor(this.targetBundle === app.bundleName ? '#FFE8F1FF' : COLOR_CARD)
            .borderRadius(14)
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
        .backgroundColor(COLOR_CARD)
        .borderRadius(12)
        .onChange((value: string) => {
          this.newAppName = value;
        })
      TextInput({ placeholder: '应用Bundle，例如 com.example.app', text: this.newAppBundle })
        .type(InputType.Normal)
        .height(42)
        .backgroundColor(COLOR_CARD)
        .borderRadius(12)
        .onChange((value: string) => {
          this.newAppBundle = value.trim();
        })
      Button('添加并选择')
        .width('100%')
        .height(42)
        .backgroundColor(COLOR_BLUE)
        .enabled(this.newAppBundle.trim().length > 0)
        .onClick(() => {
          void this.addCommonApp();
        })
    }
    .width('100%')
    .height('100%')
    .padding(20)
    .backgroundColor(COLOR_BG)
  }

  @Builder
  private targetSheet() {
    Column({ space: 14 }) {
      Row() {
        Text('Charles 目标')
          .fontSize(22)
          .fontWeight(FontWeight.Bold)
          .layoutWeight(1)
        Button('完成')
          .fontSize(14)
          .height(34)
          .backgroundColor(COLOR_BLUE)
          .onClick(() => {
            this.showTargetSheet = false;
          })
      }
      .width('100%')

      Text('IPv4 地址')
        .fontSize(13)
        .fontColor(COLOR_SUB)
        .width('100%')
      TextInput({ placeholder: '例如 192.168.1.100', text: this.targetIp })
        .type(InputType.Normal)
        .height(46)
        .backgroundColor(COLOR_CARD)
        .borderRadius(12)
        .enabled(this.status !== 'running')
        .onChange((value: string) => {
          this.targetIp = value.trim();
        })

      Text('端口')
        .fontSize(13)
        .fontColor(COLOR_SUB)
        .width('100%')
      TextInput({ placeholder: '8888', text: this.targetPort })
        .type(InputType.Number)
        .height(46)
        .backgroundColor(COLOR_CARD)
        .borderRadius(12)
        .enabled(this.status !== 'running')
        .onChange((value: string) => {
          this.targetPort = value;
        })

      Row({ space: 10 }) {
        Button('测试连通性')
          .layoutWeight(1)
          .height(44)
          .fontSize(15)
          .fontColor(COLOR_BLUE)
          .backgroundColor('#FFEDF4FF')
          .enabled(!this.busy && this.status !== 'running')
          .onClick(() => {
            void this.testConnectivity();
          })
        Button('使用并关闭')
          .layoutWeight(1)
          .height(44)
          .fontSize(15)
          .backgroundColor(COLOR_BLUE)
          .onClick(() => {
            if (this.validateTarget()) {
              this.showTargetSheet = false;
            }
          })
      }
      .width('100%')

      if (this.status === 'running') {
        Text('代理运行中，目标地址不可修改。')
          .fontSize(12)
          .fontColor(COLOR_SUB)
          .width('100%')
      }

      Divider()
      Text('历史记录')
        .fontSize(15)
        .fontWeight(FontWeight.Medium)
        .width('100%')

      List({ space: 8 }) {
        ForEach(this.records, (record: ProxyRecord) => {
          ListItem() {
            this.historyRow(record)
          }
        }, (record: ProxyRecord) => `sheet_${record.ip}:${record.port}`)
      }
      .width('100%')
      .layoutWeight(1)
      .scrollBar(BarState.Off)
    }
    .width('100%')
    .height('100%')
    .padding(20)
    .backgroundColor(COLOR_BG)
  }

  @Builder
  private logSheet() {
    Column({ space: 12 }) {
      Row() {
        Text('内核日志')
          .fontSize(22)
          .fontWeight(FontWeight.Bold)
          .layoutWeight(1)
        Button('清空')
          .fontSize(14)
          .height(34)
          .fontColor(COLOR_RED)
          .backgroundColor('#FFFFEEEE')
          .onClick(() => {
            this.logs = [];
          })
        Button('完成')
          .fontSize(14)
          .height(34)
          .backgroundColor(COLOR_BLUE)
          .margin({ left: 8 })
          .onClick(() => {
            this.showLogs = false;
          })
      }
      .width('100%')

      if (this.logs.length === 0) {
        Text('暂无日志。')
          .fontSize(14)
          .fontColor(COLOR_SUB)
          .width('100%')
          .padding(16)
      } else {
        List({ space: 6 }) {
          ForEach(this.logs, (line: string) => {
            ListItem() {
              Text(line)
                .fontSize(12)
                .fontColor('#FF3C3C43')
                .lineHeight(18)
                .width('100%')
                .padding(10)
                .backgroundColor(COLOR_CARD)
                .borderRadius(10)
            }
          }, (line: string, index: number) => `${index}_${line}`)
        }
        .width('100%')
        .layoutWeight(1)
        .scrollBar(BarState.Auto)
      }
    }
    .width('100%')
    .height('100%')
    .padding(20)
    .backgroundColor(COLOR_BG)
  }

  build() {
    Column() {
      if (this.currentTab === 0) {
        this.overviewPage()
      } else if (this.currentTab === 1) {
        this.trafficPage()
      } else if (this.currentTab === 2) {
        this.connectionPage()
      } else {
        this.settingsPage()
      }

      this.bottomBar()
    }
    .width('100%')
    .height('100%')
    .backgroundColor(COLOR_BG)
    .bindSheet(this.showAppPicker, this.appPickerSheet(), {
      height: SheetSize.LARGE,
      showClose: false,
      shouldDismiss: (dismiss: SheetDismiss) => {
        this.showAppPicker = false;
        dismiss.dismiss();
      }
    })
  }
}
