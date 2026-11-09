import nativeVpn from 'libcharles_vpn.so';

// 前三个方法是需求指定的控制面接口。attachTunFd 和事件回调是官方
// VpnConnection.create() 返回 fd 后所需的进程内桥接，不是额外 VPN 方案。
export interface NativeVpnApi {
  startVpnProxy(targetIp: string, targetPort: number): void;
  stopVpnProxy(): void;
  isVpnRunning(): boolean;
  attachTunFd(tunFd: number): void;
  setVpnEventCallback(callback: ((message: string) => void) | null): void;
}

export const vpnNative: NativeVpnApi = nativeVpn as NativeVpnApi;
