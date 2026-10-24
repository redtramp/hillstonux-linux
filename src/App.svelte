<script lang='ts'>
  import { onDestroy, onMount } from 'svelte';
  import {
    vpnConnect,
    vpnDisconnect,
    vpnState,
    loadConfig,
    saveConfig,
    onVpnEvent,
  } from './lib/daemon';
  import type { VpnStateDto, LoginConfig } from './lib/daemon';

  let server = '';
  let port = 4433;
  let user = '';
  let password = '';
  let showPassword = false;
  // false = 分流（默认，只把服务端下发的子网走隧道，外网保活）；
  // true = 全隧道（接管默认路由，与 Python 参考实现行为一致）
  let fullTunnel = false;
  let status: VpnStateDto = { phase: 'idle' };
  let errorMsg = '';

  function formatBytes(n: number): string {
    if (n < 1024) return n + ' B';
    if (n < 1024 * 1024) return (n / 1024).toFixed(1) + ' KB';
    if (n < 1024 * 1024 * 1024) return (n / 1024 / 1024).toFixed(1) + ' MB';
    return (n / 1024 / 1024 / 1024).toFixed(1) + ' GB';
  }

  const STEP_LABELS: Record<string, string> = {
    tcp: '连接服务器',
    auth: '认证',
    client_info: '客户端信息',
    wait_network: '获取网络配置',
    exchange_key: '交换密钥',
    privileged: '等待授权',
  };

  function statusMeta(p: VpnStateDto): { label: string; tone: string } {
    switch (p.phase) {
      case 'connecting':
        return {
          label: '连接中' + (p.step ? ' · ' + (STEP_LABELS[p.step] ?? p.step) : ''),
          tone: 'busy',
        };
      case 'handshaking':
        return { label: '握手协商中', tone: 'busy' };
      case 'connected':
        return { label: '已连接', tone: 'ok' };
      case 'reconnecting':
        return { label: '重连中 · 第 ' + (p.attempt ?? 0) + ' 次', tone: 'busy' };
      case 'disconnecting':
        return { label: '断开中', tone: 'busy' };
      case 'error':
        return { label: '连接错误', tone: 'err' };
      default:
        return { label: '未连接', tone: 'idle' };
    }
  }

  $: meta = statusMeta(status);
  $: busy =
    status.phase === 'connecting' ||
    status.phase === 'handshaking' ||
    status.phase === 'reconnecting' ||
    status.phase === 'disconnecting';
  $: connected = status.phase === 'connected';

  async function refreshState() {
    try {
      status = await vpnState();
    } catch (e) {
      // 守护进程可能尚未启动
    }
  }

  async function doConnect() {
    errorMsg = '';
    status = { phase: 'connecting', step: 'init' };
    try {
      const cfg: LoginConfig = { server, port, username: user, password };
      try {
        await saveConfig(cfg);
      } catch (e) {
        // best-effort
      }
      await vpnConnect({ server, port, user, password, full_tunnel: fullTunnel });
    } catch (e) {
      errorMsg = String(e);
    }
  }

  async function doDisconnect() {
    errorMsg = '';
    try {
      await vpnDisconnect();
    } catch (e) {
      errorMsg = String(e);
    }
  }

  async function loadConfigValues() {
    try {
      const cfg: LoginConfig = await loadConfig();
      if (cfg.server) server = cfg.server;
      if (cfg.port) port = cfg.port;
      if (cfg.username) user = cfg.username;
      if (cfg.password) password = cfg.password;
    } catch (e) {
      // 忽略：首次启动可能无 config.json
    }
  }

  let unlisten: (() => void) | undefined;

  onDestroy(() => {
    unlisten?.();
  });

  onMount(async () => {
    await loadConfigValues();
    await refreshState();
    try {
      unlisten = await onVpnEvent((payload) => {
        if (!payload) return;
        if (payload.type === 'state_changed') {
          status = payload.state;
        } else if (payload.type === 'log_line' && payload.level === 'error') {
          errorMsg = payload.msg;
        }
      });
    } catch (e) {
      // 事件通道注册失败：状态推送不可用，明确提示而不是静默挂掉。
      errorMsg = '事件通道初始化失败：' + String(e);
    }
  });
</script>

<main>
  <header class='topbar'>
    <div class='brand'>
      <svg class='brand-icon' viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='2' stroke-linecap='round' stroke-linejoin='round' aria-hidden='true'>
        <path d='M12 2 4 5v6c0 5 3.5 8 8 11 4.5-3 8-6 8-11V5l-8-3Z' />
        <path d='m9 12 2 2 4-4' />
      </svg>
      <div class='brand-text'>
        <span class='brand-name'>Hillstonux</span>
        <span class='brand-sub'>SSL VPN 客户端</span>
      </div>
    </div>
    <div class='status-pill {meta.tone}'>
      {#if busy}<span class='dot spin'></span>{:else if connected}<span class='dot'></span>{:else if status.phase === 'error'}<span class='dot'></span>{/if}
      <span>{meta.label}</span>
    </div>
  </header>

  <section class='card'>
    <div class='field'>
      <span class='ico' aria-hidden='true'>
        <svg viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'><rect x='2' y='3' width='20' height='14' rx='2' /><path d='M8 21h8M12 17v4' /></svg>
      </span>
      <input bind:value={server} aria-label='服务器地址' placeholder='服务器地址，如 sslvpn.example.com' autocomplete='off' spellcheck='false' />
    </div>
    <div class='field'>
      <span class='ico' aria-hidden='true'>
        <svg viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'><circle cx='12' cy='12' r='9' /><path d='M3 12h18M12 3a14 14 0 0 1 0 18M12 3a14 14 0 0 0 0 18' /></svg>
      </span>
      <input type='number' bind:value={port} aria-label='端口' min='1' max='65535' />
    </div>
    <div class='field'>
      <span class='ico' aria-hidden='true'>
        <svg viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'><circle cx='12' cy='8' r='4' /><path d='M4 21c0-4 4-6 8-6s8 2 8 6' /></svg>
      </span>
      <input bind:value={user} aria-label='用户名' placeholder='用户名' autocomplete='off' spellcheck='false' />
    </div>
    <div class='field'>
      <span class='ico' aria-hidden='true'>
        <svg viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'><rect x='4' y='10' width='16' height='11' rx='2' /><path d='M8 10V7a4 4 0 0 1 8 0v3' /></svg>
      </span>
      {#if showPassword}
        <input type='text' bind:value={password} aria-label='密码' placeholder='密码' autocomplete='off' spellcheck='false' />
      {:else}
        <input type='password' bind:value={password} aria-label='密码' placeholder='密码' autocomplete='off' spellcheck='false' />
      {/if}
      <button type='button' class='toggle' on:click={() => (showPassword = !showPassword)} aria-label={showPassword ? '隐藏密码' : '显示密码'} title={showPassword ? '隐藏密码' : '显示密码'}>
        {#if showPassword}
          <svg viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'><path d='M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7-10-7-10-7Z' /><circle cx='12' cy='12' r='3' /><path d='m4 4 16 16' /></svg>
        {:else}
          <svg viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'><path d='M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7-10-7-10-7Z' /><circle cx='12' cy='12' r='3' /></svg>
        {/if}
      </button>
    </div>
    <label class='tunnel-opt'>
      <input type='checkbox' bind:checked={fullTunnel} />
      <span>全隧道<span class='tunnel-hint'>（默认分流：仅服务端下发的子网走 VPN，外网保持直连；勾选后所有流量都走隧道）</span></span>
    </label>
  </section>

  <section class='actions'>
    <button class='btn primary' on:click={doConnect} disabled={busy || connected}>连接</button>
    <button class='btn' on:click={doDisconnect} disabled={!connected}>断开</button>
  </section>

  <section class='card detail'>
    {#if connected}
      <div class='stat-row'>
        <div class='stat'>
          <span class='stat-ico down' aria-hidden='true'><svg viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'><path d='M12 5v14M5 12l7 7 7-7' /></svg></span>
          <div><span class='stat-val'>{formatBytes(status.bytes_in ?? 0)}</span><span class='stat-label'>下行</span></div>
        </div>
        <div class='stat'>
          <span class='stat-ico up' aria-hidden='true'><svg viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'><path d='M12 19V5M5 12l7-7 7 7' /></svg></span>
          <div><span class='stat-val'>{formatBytes(status.bytes_out ?? 0)}</span><span class='stat-label'>上行</span></div>
        </div>
      </div>
      <p class='uptime'>已连接 {status.since_secs ?? 0}s</p>
    {:else if status.phase === 'reconnecting'}
      <p class='muted'>{meta.label}，{status.next_in_secs ?? 0}s 后重试</p>
    {:else if status.phase === 'error'}
      <p class='err' role='alert'>{status.message ?? errorMsg ?? '连接失败'}</p>
    {:else if busy}
      <p class='muted'>{meta.label}…</p>
    {:else}
      <p class='muted'>填写服务器信息后点击“连接”。</p>
    {/if}
  </section>

  {#if errorMsg && status.phase !== 'error'}
    <p class='err inline' role='alert'>{errorMsg}</p>
  {/if}
</main>

<style>
  :global(html),
  :global(body) {
    margin: 0;
    height: 100%;
    background: #0b1220;
  }
  main {
    max-width: 440px;
    margin: 0 auto;
    padding: 18px 18px 24px;
    box-sizing: border-box;
    color: #e2e8f0;
    font-family: system-ui, -apple-system, 'Segoe UI', sans-serif;
    display: flex;
    flex-direction: column;
    gap: 14px;
    min-height: 100vh;
  }
  .topbar {
    display: flex;
    align-items: center;
    justify-content: space-between;
  }
  .brand {
    display: flex;
    align-items: center;
    gap: 10px;
  }
  .brand-icon {
    width: 30px;
    height: 30px;
    color: #38bdf8;
  }
  .brand-text {
    display: flex;
    flex-direction: column;
    line-height: 1.1;
  }
  .brand-name {
    font-size: 16px;
    font-weight: 600;
    letter-spacing: 0.3px;
  }
  .brand-sub {
    font-size: 11px;
    color: #7c8aa0;
  }
  .status-pill {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 4px 10px;
    border-radius: 999px;
    font-size: 12px;
    border: 1px solid rgba(148, 163, 184, 0.2);
    color: #94a3b8;
    background: rgba(148, 163, 184, 0.08);
  }
  .status-pill .dot {
    width: 7px;
    height: 7px;
    border-radius: 50%;
    background: #94a3b8;
  }
  .status-pill.ok {
    color: #4ade80;
    border-color: rgba(74, 222, 128, 0.35);
    background: rgba(74, 222, 128, 0.1);
  }
  .status-pill.ok .dot {
    background: #4ade80;
  }
  .status-pill.busy {
    color: #38bdf8;
    border-color: rgba(56, 189, 248, 0.35);
    background: rgba(56, 189, 248, 0.1);
  }
  .status-pill.busy .dot {
    background: #38bdf8;
  }
  .status-pill.err {
    color: #f87171;
    border-color: rgba(248, 113, 113, 0.35);
    background: rgba(248, 113, 113, 0.1);
  }
  .status-pill.err .dot {
    background: #f87171;
  }
  .dot.spin {
    animation: pulse 1s ease-in-out infinite;
  }
  @keyframes pulse {
    0%,
    100% {
      opacity: 0.35;
    }
    50% {
      opacity: 1;
    }
  }
  .card {
    background: #111c2e;
    border: 1px solid rgba(148, 163, 184, 0.12);
    border-radius: 12px;
    padding: 12px;
  }
  .field {
    display: flex;
    align-items: center;
    gap: 8px;
    background: #0b1220;
    border: 1px solid rgba(148, 163, 184, 0.15);
    border-radius: 9px;
    padding: 0 10px;
    margin-bottom: 10px;
    transition: border-color 0.15s ease, box-shadow 0.15s ease;
  }
  .tunnel-opt {
    display: flex;
    align-items: flex-start;
    gap: 8px;
    padding: 2px 4px 0;
    font-size: 13px;
    color: #cbd5e1;
    cursor: pointer;
    user-select: none;
  }
  .tunnel-opt input[type='checkbox'] {
    margin-top: 2px;
    accent-color: #38bdf8;
    flex-shrink: 0;
  }
  .tunnel-hint {
    color: #64748b;
    font-size: 12px;
  }
  .field:focus-within {
    border-color: #38bdf8;
    box-shadow: 0 0 0 3px rgba(56, 189, 248, 0.15);
  }
  .field:last-child {
    margin-bottom: 0;
  }
  .ico {
    width: 18px;
    height: 18px;
    color: #64748b;
    flex: none;
  }
  .field input {
    flex: 1;
    min-width: 0;
    background: transparent;
    border: 0;
    outline: none;
    color: #e2e8f0;
    font-size: 14px;
    padding: 11px 0;
  }
  .field input::placeholder {
    color: #5b6b82;
  }
  .toggle {
    flex: none;
    background: transparent;
    border: 0;
    cursor: pointer;
    color: #64748b;
    padding: 4px;
    border-radius: 6px;
    display: inline-flex;
    transition: color 0.15s ease, background 0.15s ease;
  }
  .toggle:hover {
    color: #cbd5e1;
    background: rgba(148, 163, 184, 0.1);
  }
  .toggle svg {
    width: 18px;
    height: 18px;
  }
  .actions {
    display: flex;
    gap: 10px;
  }
  .btn {
    flex: 1;
    padding: 11px 0;
    border-radius: 9px;
    border: 1px solid rgba(148, 163, 184, 0.2);
    background: #1b2a40;
    color: #e2e8f0;
    font-size: 14px;
    font-weight: 500;
    cursor: pointer;
    transition: background 0.15s ease, border-color 0.15s ease, opacity 0.15s ease;
  }
  .btn:hover:not(:disabled) {
    background: #23344f;
  }
  .btn.primary {
    background: #0ea5e9;
    border-color: #0ea5e9;
    color: #04121f;
    font-weight: 600;
  }
  .btn.primary:hover:not(:disabled) {
    background: #38bdf8;
  }
  .btn:disabled {
    opacity: 0.45;
    cursor: default;
  }
  .detail {
    min-height: 56px;
    display: flex;
    flex-direction: column;
    justify-content: center;
  }
  .stat-row {
    display: flex;
    gap: 10px;
  }
  .stat {
    flex: 1;
    display: flex;
    align-items: center;
    gap: 8px;
    background: #0b1220;
    border-radius: 8px;
    padding: 8px 10px;
  }
  .stat-ico {
    width: 18px;
    height: 18px;
    flex: none;
  }
  .stat-ico.down {
    color: #4ade80;
  }
  .stat-ico.up {
    color: #38bdf8;
  }
  .stat-val {
    font-size: 14px;
    font-weight: 600;
    display: block;
  }
  .stat-label {
    font-size: 11px;
    color: #7c8aa0;
  }
  .uptime {
    margin: 8px 0 0;
    font-size: 12px;
    color: #7c8aa0;
  }
  .muted {
    margin: 0;
    color: #7c8aa0;
    font-size: 13px;
  }
  .err {
    margin: 0;
    color: #f87171;
    font-size: 13px;
  }
  .err.inline {
    margin-top: 2px;
  }
</style>
