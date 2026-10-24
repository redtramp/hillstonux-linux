// Type definitions mirroring the daemon's IPC and profile storage
// (`crates/hillstonux-daemon/src/ipc.rs`, `src-tauri/src/profile.rs`).
// Keep these in sync manually (or generate via a build script later).
//
// Pure type layer: all Tauri command wrappers live in `daemon.ts`.

export interface Profile {
  name: string;
  server: string;
  port: number;
  username: string;
  password_ref: string;
  auto_connect: boolean;
}

export interface ProfileSettings {
  minimize_to_tray: boolean;
  start_minimized: boolean;
  auto_reconnect: boolean;
  max_reconnect_attempts: number;
}

export interface ProfilesFile {
  settings: ProfileSettings;
  profile: Profile | null;
}

// Login form values persisted to `~/.config/hillstonux/config.json`.
export interface LoginConfig {
  server: string;
  port: number;
  username: string;
  password: string;
}
