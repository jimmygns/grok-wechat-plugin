import { execFileSync, spawn } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  clearPid,
  findAllMonitorPids,
  homeDir,
  isMcpServerProcess,
   isMonitorProcess,
  listAccounts,
  listAllProcessPids,
  loadState,
} from "./store.js";

const PLUGIN_DIR_NAMES = new Set(["grok-wechat-plugin", "grok-wechat"]);
const GROK_BOX_HOME = "/home/box";

function hasGrokWechatManifest(dir) {
  try {
    const manifestPath = path.join(dir, "plugin.json");
    if (!fs.existsSync(manifestPath)) return false;
    const data = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
    return data?.name === "grok-wechat";
  } catch {
    return false;
  }
}

function isPluginDir(dir) {
  if (!dir || !fs.existsSync(dir)) return false;
  const resolved = path.resolve(dir);
  if (resolved === "/" || resolved === os.homedir() || resolved === GROK_BOX_HOME || resolved === "/workspace") {
    return false;
  }
  return PLUGIN_DIR_NAMES.has(path.basename(resolved)) && hasGrokWechatManifest(resolved);
}

export function knownStateHomes() {
  const homes = new Set([
    path.join(GROK_BOX_HOME, ".grok-wechat"),
    path.join(os.homedir(), ".grok-wechat"),
    "/workspace/.grok-wechat",
  ]);
  const envHome = process.env.GROK_WECHAT_HOME?.trim();
  if (envHome) homes.add(path.resolve(envHome));
  homes.add(homeDir());
  return [...homes];
}

export function knownPluginDirs() {
  const dirs = new Set([
    path.join(GROK_BOX_HOME, "grok-wechat-plugin"),
    path.join(GROK_BOX_HOME, "grok-wechat"),
    "/workspace/grok-wechat-plugin",
    "/workspace/grok-wechat",
  ]);
  try {
    const here = path.dirname(fileURLToPath(import.meta.url));
    const parent = path.dirname(here);
    if (isPluginDir(parent)) dirs.add(parent);
  } catch {
    // ignore
  }
  return [...dirs];
}

export function stopAllMonitors() {
  const stopped = [];
  for (const pid of findAllMonitorPids()) {
    if (!isMonitorProcess(pid)) continue;
    try {
      process.kill(pid, "SIGTERM");
      stopped.push(pid);
    } catch {
      // already gone
    }
  }
  clearPid();
  return [...new Set(stopped)];
}

function removeDir(target) {
  if (!target || !fs.existsSync(target)) return false;
  const resolved = path.resolve(target);
  if (resolved === "/" || resolved === os.homedir() || resolved === GROK_BOX_HOME || resolved === "/workspace") {
    return false;
  }
  fs.rmSync(resolved, { recursive: true, force: true });
  return true;
}

export function removeAllStateHomes() {
  const removed = [];
  for (const dir of knownStateHomes()) {
    if (removeDir(dir)) removed.push(dir);
  }
  return [...new Set(removed)];
}

export function removeAllPluginDirs() {
  const removed = [];
  for (const dir of knownPluginDirs()) {
    if (!isPluginDir(dir)) continue;
    if (removeDir(dir)) removed.push(dir);
  }
  return removed;
}

function lineMatchesAutostart(line) {
  const text = line.trim();
  if (!text || text.startsWith("#")) return false;
  return /grok-wechat|ensure-monitor\.sh/.test(text);
}

export function stripAutostartFromFile(filePath) {
  if (!filePath || !fs.existsSync(filePath)) return false;
  const original = fs.readFileSync(filePath, "utf8");
  const lines = original.split("\n");
  const kept = lines.filter((line) => !lineMatchesAutostart(line));
  if (kept.length === lines.length) return false;
  const next = kept.join("\n");
  if (next.trim()) {
    fs.writeFileSync(filePath, next.endsWith("\n") ? next : `${next}\n`);
  } else {
    // Preserve profile file rather than deleting user's .bashrc / .profile
    fs.writeFileSync(filePath, "");
  }
  return true;
}

export function removeAutostartEntries() {
  const touched = [];
  const profileFiles = new Set([
    path.join(GROK_BOX_HOME, ".profile"),
    path.join(GROK_BOX_HOME, ".bashrc"),
    path.join(GROK_BOX_HOME, ".bash_profile"),
    path.join(os.homedir(), ".profile"),
    path.join(os.homedir(), ".bashrc"),
    path.join(os.homedir(), ".bash_profile"),
  ]);
  for (const file of profileFiles) {
    if (stripAutostartFromFile(file)) touched.push(file);
  }
  try {
    const current = execFileSync("crontab", ["-l"], {
      encoding: "utf8",
      timeout: 3000,
      stdio: ["ignore", "pipe", "ignore"],
    }).trim();
    if (current) {
      const lines = current.split("\n");
      const kept = lines.filter((line) => !lineMatchesAutostart(line));
      if (kept.length !== lines.length) {
        if (!kept.some((l) => l.trim())) {
          try {
            execFileSync("crontab", ["-r"], { timeout: 3000, stdio: "ignore" });
          } catch {
            // ignore
          }
        } else {
          const tmp = path.join(os.tmpdir(), `grok-wechat-crontab-${process.pid}-${Date.now()}`);
          fs.writeFileSync(tmp, `${kept.join("\n")}\n`, { mode: 0o600 });
          try {
            execFileSync("crontab", [tmp], { timeout: 3000, stdio: "ignore" });
          } finally {
            try {
              fs.unlinkSync(tmp);
            } catch {
              // ignore
            }
          }
        }
        touched.push("crontab");
      }
    }
  } catch {
    // crontab not installed or user has no crontab
  }
  return touched;
}

function mcpStillRunning() {
  for (const pid of listAllProcessPids()) {
    if (isMcpServerProcess(pid)) return true;
  }
  return false;
}

export function connectorAbandoned() {
  // Never auto-uninstall based on transient MCP process absence: MCP hosts may
  // stop idle stdio servers or restart them across turns/reboots.
  return false;
}

export function touchConnectorActive() {
  // Retained as a safe no-op for compatibility.
}

export function scheduleDeferredUninstall() {
  try {
    const targets = [
      ...knownStateHomes(),
      ...knownPluginDirs().filter((d) => isPluginDir(d)),
    ];
    if (!targets.length) return true;
    const script = [
      "sleep 2",
      'for d in "$@"; do',
      '  [ -n "$d" ] && [ "$d" != "/" ] && [ "$d" != "/home/box" ] && [ "$d" != "/workspace" ] && rm -rf -- "$d" 2>/dev/null || true',
      "done",
    ].join("\n");
    const child = spawn("sh", ["-c", script, "grok-wechat-deferred-uninstall", ...targets], {
      detached: true,
      stdio: "ignore",
      env: process.env,
    });
    child.unref();
    return true;
  } catch {
    return false;
  }
}

export function registerShutdownCleanup() {
  // Retained as a safe no-op: closing MCP stdio must never trigger uninstall.
}

function collectDedicatedAssistants() {
  return listAccounts(loadState())
    .map((a) => ({
      ilink_bot_id: a.ilinkBotId,
      assistant_id: a.dedicatedAssistant?.id || "",
      assistant_name: a.dedicatedAssistant?.name || "",
    }))
    .filter((a) => a.assistant_id || a.assistant_name);
}

function platformCleanup(dedicatedAssistants) {
  const sidebarNames = dedicatedAssistants.map((a) => a.assistant_name).filter(Boolean);
  return {
    connector: "grok-wechat",
    routine_names: ["微信入站唤醒", "微信监听保活"],
    dedicated_assistants_sidebar_delete: dedicatedAssistants,
    dedicated_assistant_sidebar_names: sidebarNames,
    execute: [
      "从 Grok Bot Settings 卸载 grok-wechat 连接器（若仍存在）",
      "删除安装助手上 Routine「微信入站唤醒」与「微信监听保活」",
      "删除其他助手上残留的同名 Routine",
      sidebarNames.length
        ? `告知用户在侧栏右键 → 删除专属助手：${sidebarNames.join("、")}`
        : "告知用户在侧栏删除绑定期间创建的专属助手",
    ],
  };
}

export function runUninstall({ deferPluginRemoval = false } = {}) {
  const dedicatedAssistants = collectDedicatedAssistants();
  const stoppedPids = stopAllMonitors();
  const removedAutostart = removeAutostartEntries();
  const removedStateDirs = removeAllStateHomes();
  let removedPluginDirs = [];
  let deferredPluginRemoval = false;

  if (deferPluginRemoval || mcpStillRunning()) {
    scheduleDeferredUninstall();
    deferredPluginRemoval = true;
  } else {
    removedPluginDirs = removeAllPluginDirs();
  }

  return {
    uninstalled: true,
    stopped_monitor_pids: stoppedPids,
    removed_state_dirs: removedStateDirs,
    removed_plugin_dirs: removedPluginDirs,
    removed_autostart: removedAutostart,
    deferred_plugin_removal: deferredPluginRemoval,
    dedicated_assistants_sidebar_delete: dedicatedAssistants,
    platform_cleanup: platformCleanup(dedicatedAssistants),
  };
}

export function uninstallWechat() {
  return runUninstall({ deferPluginRemoval: true });
}

if (process.argv.includes("--uninstall")) {
  const immediate = process.argv.includes("--immediate");
  process.stdout.write(`${JSON.stringify(runUninstall({ deferPluginRemoval: !immediate }), null, 2)}\n`);
}
