export interface NativeVpnApi {
  startVpnProxy(targetIp: string, targetPort: number): void;
  stopVpnProxy(): void;
  isVpnRunning(): boolean;
  attachTunFd(tunFd: number): void;
  setVpnEventCallback(callback: ((message: string) => void) | null): void;
}

declare const nativeVpn: NativeVpnApi;
export default nativeVpn;
