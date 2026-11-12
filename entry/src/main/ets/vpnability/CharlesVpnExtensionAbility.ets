import { Want } from '@kit.AbilityKit';
import { vpnExtension, VpnExtensionAbility } from '@kit.NetworkKit';
import { BusinessError } from '@kit.BasicServicesKit';
import { hilog } from '@kit.PerformanceAnalysisKit';
import { vpnNative } from '../common/NativeVpn';
import {
  BUNDLE_NAME,
  EVENT_ERROR,
  EVENT_READY,
  EVENT_STOPPED,
  EVENT_TRAFFIC,
  publishVpnEvent
} from '../common/VpnEvents';

const TAG: string = 'CharlesVpnExt';
const LOG_DOMAIN: number = 0xC0DE;

function errorText(error: Object): string {
  const businessError = error as BusinessError;
  return `${businessError.code ?? 'unknown'}: ${businessError.message ?? String(error)}`;
}

// 这是系统 VPN Extension + TUN，不会修改系统 Wi-Fi HTTP 代理。
// 扩展中的出栈 socket 由 protectProcessNet 保护，避免到 Charles 的流量再次进入 TUN。
export default class CharlesVpnExtensionAbility extends VpnExtensionAbility {
  private connection?: vpnExtension.VpnConnection;
  private closing: boolean = false;
  private readyPublished: boolean = false;
  private lastForwardError: string = '';
  private lastForwardErrorAt: number = 0;

  onCreate(want: Want): void {
    this.closing = false;
    void this.start(want);
  }

  onDestroy(): void {
    this.closing = true;
    void this.destroy(true);
  }

  private async start(want: Want): Promise<void> {
    try {
      // API 22 起 startVpnExtensionAbility 首次启动支持 parameters；本工程只面向 API 26。
      const targetIp: string = String(want.parameters?.targetIp ?? '');
      const targetPort: number = Number(want.parameters?.targetPort ?? 0);
      const targetBundle: string = String(want.parameters?.targetBundle ?? '').trim();
      hilog.info(LOG_DOMAIN, TAG, 'VPN target bundle: %{public}s',
        targetBundle.length > 0 ? targetBundle : '(global)');
      vpnNative.setVpnEventCallback((message: string) => {
        // 实时流量事件频率高且每条都不同，不做错误去重，直接转发给 UI。
        if (message.startsWith('trace\t')) {
          hilog.info(LOG_DOMAIN, TAG, 'trace forward len=%{public}d head=%{public}s',
            message.length, message.substring(0, 24));
          publishVpnEvent(EVENT_TRAFFIC, message);
          return;
        }
        const now: number = Date.now();
        if (message === this.lastForwardError && now - this.lastForwardErrorAt < 3000) {
          return;
        }
        this.lastForwardError = message;
        this.lastForwardErrorAt = now;
        publishVpnEvent(EVENT_ERROR, message);
      });
      vpnNative.startVpnProxy(targetIp, targetPort);
      this.connection = vpnExtension.createVpnConnection(this.context);

      // 官方 API 22+。必须在 Native 创建任何 Charles/DNS socket 前执行；只保护扩展进程。
      await this.connection.protectProcessNet();
      if (this.closing) {
        return;
      }

      const config: vpnExtension.VpnConfig = {
        addresses: [{
          address: { address: '10.66.0.2', family: 1 },
          prefixLength: 24
        }],
        routes: [{
          interface: 'vpn-tun',
          destination: {
            address: { address: '0.0.0.0', family: 1 },
            prefixLength: 0
          },
          gateway: { address: '0.0.0.0', family: 1 },
          hasGateway: false,
          isDefaultRoute: true
        }],
        // 默认路由也会收到 DNS。Native 对 UDP/53 做中继，其他 UDP/QUIC 不接管转发。
        dnsAddresses: ['223.5.5.5', '119.29.29.29'],
        mtu: 1500,
        isIPv4Accepted: true,
        isIPv6Accepted: false,
        isInternal: false,
        isBlocking: false
      };

      // 官方 trustedApplications：只代理列出的应用；与 blockedApplications 互斥。
      // 留空时完全不设置该字段，维持全部应用按 routes 进入 VPN 的原有行为。
      if (targetBundle.length > 0) {
        config.trustedApplications = [targetBundle];
      }

      // 最新公开接口是 create(config): Promise<number>；不是旧示例的 setUp()。
      const tunFd: number = await this.connection.create(config);
      if (this.closing) {
        await this.connection.destroy();
        return;
      }
      vpnNative.attachTunFd(tunFd);
      if (!vpnNative.isVpnRunning()) {
        throw new Error('Native TUN worker did not enter running state');
      }
      this.readyPublished = true;
      publishVpnEvent(EVENT_READY, `${targetIp}:${targetPort}`);
      hilog.info(LOG_DOMAIN, TAG, 'VPN TUN proxy started');
    } catch (error) {
      const message: string = errorText(error as Object);
      hilog.error(LOG_DOMAIN, TAG, 'VPN start failed: %{public}s', message);
      await this.destroy(false);
      publishVpnEvent(EVENT_ERROR, message);
    }
  }

  private async destroy(notifyStopped: boolean): Promise<void> {
    // 先停 Native 并关闭 dup 出来的 TUN fd，再由 destroy 释放官方原始 VPN 会话/fd。
    vpnNative.stopVpnProxy();
    vpnNative.setVpnEventCallback(null);
    const connection = this.connection;
    this.connection = undefined;
    // 系统可在 onDestroy 返回后立即杀死 :vpn 进程，不能等异步 destroy 完成后才通知 UI。
    if (notifyStopped) {
      publishVpnEvent(EVENT_STOPPED, '');
    }
    if (connection) {
      try {
        await connection.destroy();
      } catch (error) {
        hilog.error(LOG_DOMAIN, TAG, 'VPN destroy failed: %{public}s', errorText(error as Object));
      }
    }
    if (!notifyStopped && this.readyPublished) {
      publishVpnEvent(EVENT_ERROR, 'VPN 转发已异常停止');
    }
  }
}
