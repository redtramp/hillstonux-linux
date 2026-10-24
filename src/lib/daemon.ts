import { invoke } from '@tauri-apps/api/core';
import { listen, type UnlistenFn } from '@tauri-apps/api/event';
import type { LoginConfig, ProfilesFile } from './ipc';

export interface VpnStateDto {
  phase: string;
  step?: string;
  since_secs?: number;
  bytes_in?: number;
  bytes_out?: number;
  attempt?: number;
  next_in_secs?: number;
  code?: number;
  message?: string;
}

export interface ConnectParams {
  server: string;
  port: number;
  user: string;
  password: string;
  password_ref?: string;
  /** true = 全隧道（接管默认路由）；false（默认）= 分流，只走服务端下发的子网，外网保活 */
  full_tunnel?: boolean;
}

export async function vpnConnect(p: ConnectParams): Promise<void> {
  await invoke('vpn_connect', { params: p });
}

export async function vpnDisconnect(): Promise<void> {
  await invoke('vpn_disconnect');
}

export async function vpnState(): Promise<VpnStateDto> {
  return await invoke('vpn_state');
}

export async function loadProfiles(): Promise<ProfilesFile> {
  return await invoke<ProfilesFile>('load_profiles');
}

export async function saveProfiles(file: ProfilesFile): Promise<void> {
  await invoke('save_profiles', { file });
}

export async function savePassword(profileName: string, password: string): Promise<string> {
  return await invoke('save_password', { profileName, password });
}

export async function deletePassword(profileName: string): Promise<void> {
  await invoke('delete_password', { profileName });
}

export async function getPassword(profileName: string): Promise<string> {
  return await invoke('get_password', { profileName });
}

export async function daemonSocketPath(): Promise<string> {
  return await invoke('daemon_socket_path');
}

// Payload of the `vpn-event` Tauri event — mirrors the daemon's IPC event
// types (see crates/hillstonux-daemon/src/ipc.rs).
export type VpnEventPayload =
  | { type: 'state_changed'; state: VpnStateDto }
  | { type: 'log_line'; level: string; msg: string }
  | { type: 'stats'; bytes_in: number; bytes_out: number };

export async function onVpnEvent(handler: (payload: VpnEventPayload) => void): Promise<UnlistenFn> {
  return await listen<VpnEventPayload>('vpn-event', (event) => handler(event.payload));
}

export type { LoginConfig };

export async function loadConfig(): Promise<LoginConfig> {
  return await invoke<LoginConfig>('load_config');
}

export async function saveConfig(cfg: LoginConfig): Promise<void> {
  await invoke('save_config', { cfg });
}
