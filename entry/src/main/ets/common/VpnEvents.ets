import { commonEventManager } from '@kit.BasicServicesKit';
import { hilog } from '@kit.PerformanceAnalysisKit';

export const BUNDLE_NAME: string = 'com.zj.charlesvpn';
export const VPN_ABILITY_NAME: string = 'CharlesVpnExtensionAbility';
export const VPN_EVENT: string = 'com.zj.charlesvpn.VPN_STATE';
export const EVENT_READY: number = 1;
export const EVENT_STOPPED: number = 2;
export const EVENT_ERROR: number = 3;
export const EVENT_TRAFFIC: number = 4;

// UIAbility 与 VPN 扩展可处于不同进程，Native 单例不能承担跨进程 UI 状态同步。
// 自定义公共事件限定发布者与接收者 bundleName，不发送 HTTP 报文或其他敏感数据。
export function publishVpnEvent(code: number, message: string): void {
  commonEventManager.publish(VPN_EVENT, {
    bundleName: BUNDLE_NAME,
    code: code,
    data: message,
    isOrdered: false,
    isSticky: false
  }, (error) => {
    if (error) {
      hilog.error(0xC0DE, 'CharlesVpn', 'Publish VPN event failed: %{public}s', error.message);
    }
  });
}
