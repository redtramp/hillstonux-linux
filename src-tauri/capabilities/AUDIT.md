# Capabilities 权限审计

本文件由 `scripts/audit-capabilities.py` 自动生成结论。该脚本交叉比对：
- 前端 `src/` 中的 `invoke(...)` / `listen(...)` 调用；
- `src-tauri/src` 中 `#[tauri::command]` 定义的命令；
- `src-tauri/capabilities/*.json` 中授予的权限。

## 审计结论（当前）

授予的权限（3 项）：
- `core:default`
- `core:event:allow-listen`
- `core:event:allow-emit`

前端调用覆盖：
- 10 个 `invoke` 调用，全部是应用自定义命令
  （vpn_connect / vpn_disconnect / vpn_state / load_config / save_config /
  load_profiles / save_profiles / save_password / delete_password /
  daemon_socket_path）。Tauri v2 中应用自身命令默认放行，无需单独授权。
- 1 个 `listen` 调用：`vpn-event`，已被 `core:event:allow-listen` 覆盖。

结果：**无缺失权限，审计通过。**

## 最小权限建议

`core:default` 是一个宽泛预设，包含大量核心 API
（window / webview / menu / tray / path / image / app / resources 等）。
本应用实际只用到其中一小部分。若希望收紧权限，可在 capability 中
仅声明真正需要的项，例如：

```json
{
  "permissions": [
    "core:event:allow-listen",
    "core:event:allow-emit",
    "core:app:allow-exit",
    "core:window:allow-show",
    "core:window:allow-hide",
    "core:window:allow-set-focus",
    "core:tray:allow-set-tooltip"
  ]
}
```

（注意：收紧后需重新跑 `python3 scripts/audit-capabilities.py` 确认无遗漏。）

## 运行方式

    python3 scripts/audit-capabilities.py

退出码 0 表示无缺失权限；非 0 表示发现缺口（可作为 CI 检查）。
