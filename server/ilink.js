import crypto from "node:crypto";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import {
  DEFAULT_BASE,
  commitUpdatesBuf,
  contextFor,
  emptyAccount,
  findAccount,
  hasAccountWake,
  hasGlobalWake,
  isAllowed,
  listAccounts,
  loadState,
  localTokenList,
  paths,
  peekInboxCount,
  rememberContext,
  requireAccount,
  resolveAccountForPeer,
  saveGlobalWake,
  saveStateSecure,
  updateState,
  upsertAccount,
} from "./store.js";

const CHANNEL_VERSION = "1.0.0";
const BOT_AGENT = "Grokbot/1.0.0";
const ILINK_APP_ID = "bot";
const ILINK_APP_CLIENT_VERSION = ((1 & 0xff) << 16) | ((0 & 0xff) << 8) | (0 & 0xff);
const CDN_BASE = "https://novac2c.cdn.weixin.qq.com/c2c";
const LONG_POLL_MS = 35_000;
const API_TIMEOUT_MS = 15_000;
const MEDIA_TIMEOUT_MS = 60_000;
const WAKE_TIMEOUT_MS = 15_000;
const MAX_MEDIA_BYTES = 100 * 1024 * 1024;
const QR_TTL_MS = 15 * 60 * 1000;
const MIN_QR_POLL_INTERVAL_MS = 1_500;
const ERR_SESSION_EXPIRED = -14;

export const ITEM = { TEXT: 1, IMAGE: 2, VOICE: 3, FILE: 4, VIDEO: 5 };
export const MSG_TYPE = { USER: 1, BOT: 2 };
export const MSG_STATE = { NEW: 0, GENERATING: 1, FINISH: 2 };
export const UPLOAD = { IMAGE: 1, VIDEO: 2, FILE: 3, VOICE: 4 };
export const TYPING = { ON: 1, OFF: 2 };

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

function randomUin() {
  return Buffer.from(String(crypto.randomBytes(4).readUInt32BE(0)), "utf8").toString("base64");
}

function clientId() {
  return `grok-wechat-${crypto.randomBytes(6).toString("hex")}`;
}

function baseInfo() {
  return { channel_version: CHANNEL_VERSION, bot_agent: BOT_AGENT };
}

function commonHeaders() {
  return {
    "iLink-App-Id": ILINK_APP_ID,
    "iLink-App-ClientVersion": String(ILINK_APP_CLIENT_VERSION),
  };
}

function postHeaders(token) {
  const headers = {
    "Content-Type": "application/json",
    AuthorizationType: "ilink_bot_token",
    "X-WECHAT-UIN": randomUin(),
    ...commonHeaders(),
  };
  if (token) headers.Authorization = `Bearer ${token}`;
  return headers;
}

function joinUrl(base, endpoint) {
  const root = base.endsWith("/") ? base : `${base}/`;
  return new URL(endpoint, root).toString();
}

function isPrivateOrReservedIp(ip) {
  const version = net.isIP(ip);
  if (version === 4) {
    const parts = ip.split(".").map(Number);
    const [a, b] = parts;
    if (a === 0 || a === 10 || a === 127) return true;
    if (a === 169 && b === 254) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    if (a === 100 && b >= 64 && b <= 127) return true;
    if (a >= 224) return true;
    return false;
  }
  if (version === 6) {
    const lower = ip.toLowerCase();
    if (lower === "::" || lower === "::1") return true;
    if (lower.startsWith("fc") || lower.startsWith("fd")) return true;
    if (/^fe[89ab]/.test(lower)) return true;
    if (lower.startsWith("::ffff:")) {
      const tail = lower.slice(7);
      if (net.isIP(tail) === 4) return isPrivateOrReservedIp(tail);
      const hexMatch = tail.match(/^([0-9a-f]{1,4}):([0-9a-f]{1,4})$/);
      if (hexMatch) {
        const hi = parseInt(hexMatch[1], 16);
        const lo = parseInt(hexMatch[2], 16);
        const v4 = `${(hi >> 8) & 0xff}.${hi & 0xff}.${(lo >> 8) & 0xff}.${lo & 0xff}`;
        return isPrivateOrReservedIp(v4);
      }
    }
    return false;
  }
  return false;
}

export function assertSafeRemoteUrl(rawUrl, { allowHttp = false, allowLoopback = false } = {}) {
  let parsed;
  try {
    parsed = new URL(String(rawUrl || ""));
  } catch {
    throw new Error(`非法 URL: ${rawUrl}`);
  }
  const okProto = parsed.protocol === "https:" || (allowHttp && parsed.protocol === "http:");
  if (!okProto) {
    throw new Error(`不允许的 URL 协议: ${parsed.protocol}`);
  }
  const host = parsed.hostname.replace(/^\[|\]$/g, "").toLowerCase();
  if (!host) throw new Error("URL 缺少主机名");
  const metadataHosts = new Set([
    "169.254.169.254",
    "169.254.170.2",
    "metadata.google.internal",
    "metadata",
    "fd00:ec2::254",
  ]);
  if (metadataHosts.has(host)) {
    throw new Error(`禁止访问元数据地址: ${host}`);
  }
  if (!allowLoopback) {
    if (host === "localhost" || host.endsWith(".localhost") || host.endsWith(".internal")) {
      throw new Error(`禁止访问内网主机: ${host}`);
    }
    if (isPrivateOrReservedIp(host)) {
      throw new Error(`禁止访问私有或保留 IP: ${host}`);
    }
  }
  return parsed.toString();
}

export function safeMediaFilename(label, fallback = "media.bin") {
  const raw = String(label ?? "");
  const base = path.win32.basename(path.posix.basename(raw));
  const cleaned = base
    .replace(/[\x00-\x1f\x7f/\\]/g, "_")
    .replace(/^\.+/, "")
    .trim()
    .slice(0, 180);
  return cleaned || fallback;
}

const BLOCKED_ROOT_PREFIXES = ["/etc", "/proc", "/sys", "/dev", "/root", "/run", "/var/run"];
const BLOCKED_PATH_SEGMENTS = new Set([
  ".ssh",
  ".gnupg",
  ".aws",
  ".kube",
  ".docker",
  ".config",
  ".git",
  ".netrc",
  ".npmrc",
  ".pypirc",
]);
const BLOCKED_BASENAMES = new Set([
  "account.json",
  "wake.json",
  "inbox.jsonl",
  "id_rsa",
  "id_ed25519",
  "id_ecdsa",
  "id_dsa",
  "authorized_keys",
  "known_hosts",
]);

function isUnderDir(candidate, dir) {
  const resolvedDir = path.resolve(dir);
  const resolvedCandidate = path.resolve(candidate);
  return resolvedCandidate === resolvedDir || resolvedCandidate.startsWith(resolvedDir + path.sep);
}

export function assertSafeOutboundMediaPath(filePath) {
  if (!filePath || typeof filePath !== "string") {
    throw new Error("文件路径不能为空");
  }
  if (!fs.existsSync(filePath)) {
    throw new Error(`文件不存在: ${filePath}`);
  }
  const realPath = fs.realpathSync(filePath);
  const stat = fs.statSync(realPath);
  if (!stat.isFile()) {
    throw new Error(`不是普通文件: ${filePath}`);
  }
  if (stat.size > MAX_MEDIA_BYTES) {
    throw new Error(`文件过大 (${stat.size} bytes)，超过上限 ${MAX_MEDIA_BYTES} bytes`);
  }

  const { home, media } = paths();
  const realMedia = fs.existsSync(media) ? fs.realpathSync(media) : path.resolve(media);
  const stateDirs = [
    home,
    path.join(os.homedir(), ".grok-wechat"),
    "/home/box/.grok-wechat",
    "/workspace/.grok-wechat",
  ].map((d) => (fs.existsSync(d) ? fs.realpathSync(d) : path.resolve(d)));

  if (!isUnderDir(realPath, realMedia)) {
    for (const stateDir of stateDirs) {
      if (isUnderDir(realPath, stateDir)) {
        throw new Error("禁止发送插件凭证或内部状态文件");
      }
    }
  }

  for (const prefix of BLOCKED_ROOT_PREFIXES) {
    if (isUnderDir(realPath, prefix)) {
      throw new Error(`禁止发送系统敏感目录文件: ${prefix}`);
    }
  }

  const base = path.basename(realPath);
  if (BLOCKED_BASENAMES.has(base) || base === ".env" || base.startsWith(".env.")) {
    throw new Error(`禁止发送敏感文件: ${base}`);
  }

  const segments = realPath.split(path.sep).filter(Boolean);
  for (const seg of segments) {
    if (BLOCKED_PATH_SEGMENTS.has(seg)) {
      throw new Error(`禁止发送敏感路径下的文件: ${seg}`);
    }
  }

  return { realPath, size: stat.size };
}

async function fetchText(url, init, timeoutMs) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, { ...init, signal: controller.signal });
    const text = await res.text();
    if (!res.ok) throw new Error(`HTTP ${res.status}: ${text.slice(0, 400)}`);
    return { text, headers: res.headers };
  } finally {
    clearTimeout(timer);
  }
}

async function fetchBufferBounded(url, init, timeoutMs, maxBytes) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, { ...init, signal: controller.signal });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const contentLength = Number(res.headers.get("content-length") || 0);
    if (Number.isFinite(contentLength) && contentLength > maxBytes) {
      throw new Error(`媒体超过大小上限 (${contentLength} > ${maxBytes})`);
    }
    if (!res.body) {
      const buf = Buffer.from(await res.arrayBuffer());
      if (buf.length > maxBytes) throw new Error(`媒体超过大小上限 (${buf.length} > ${maxBytes})`);
      return { buffer: buf, headers: res.headers };
    }
    const chunks = [];
    let total = 0;
    for await (const chunk of res.body) {
      const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      total += buf.length;
      if (total > maxBytes) {
        controller.abort();
        throw new Error(`媒体超过大小上限 (>${maxBytes})`);
      }
      chunks.push(buf);
    }
    return { buffer: Buffer.concat(chunks, total), headers: res.headers };
  } finally {
    clearTimeout(timer);
  }
}

export async function apiGet(baseUrl, endpoint, timeoutMs = API_TIMEOUT_MS) {
  const { text } = await fetchText(
    joinUrl(baseUrl, endpoint),
    { method: "GET", headers: commonHeaders() },
    timeoutMs,
  );
  return JSON.parse(text);
}

export async function apiPost(baseUrl, endpoint, body, token, timeoutMs = API_TIMEOUT_MS) {
  const { text } = await fetchText(
    joinUrl(baseUrl, endpoint),
    {
      method: "POST",
      headers: postHeaders(token),
      body: JSON.stringify({ ...body, base_info: baseInfo() }),
    },
    timeoutMs,
  );
  return JSON.parse(text);
}

function accountSummary(account) {
  return {
    ilink_bot_id: account.ilinkBotId,
    ilink_user_id: account.ilinkUserId,
    logged_in: Boolean(account.token),
    has_wake: hasAccountWake(account),
    dedicated_assistant_id: account.dedicatedAssistant?.id || "",
    dedicated_assistant_name: account.dedicatedAssistant?.name || "",
  };
}

function resolveSafeBaseUrl(candidate) {
  if (!candidate) return DEFAULT_BASE;
  try {
    return assertSafeRemoteUrl(candidate, {
      allowHttp: process.env.GROK_WECHAT_ALLOW_INSECURE_API === "1",
      allowLoopback: process.env.GROK_WECHAT_ALLOW_INSECURE_API === "1",
    });
  } catch {
    return DEFAULT_BASE;
  }
}

function applyLoginConfirm(state, last) {
  const partial = {
    token: last.bot_token,
    ilinkBotId: last.ilink_bot_id || "",
    ilinkUserId: last.ilink_user_id || "",
    baseUrl: resolveSafeBaseUrl(last.baseurl),
  };
  upsertAccount(state, partial);
  return findAccount(state, {
    ilink_bot_id: partial.ilinkBotId || undefined,
    token: partial.token,
  }) || { ...emptyAccount(), ...partial };
}

function loginBaseUrl() {
  const override = process.env.GROK_WECHAT_API_BASE?.trim();
  if (override) return resolveSafeBaseUrl(override);
  return DEFAULT_BASE;
}

export async function loginStart() {
  const state = loadState();
  const baseUrl = loginBaseUrl();
  const data = await apiPost(baseUrl, "ilink/bot/get_bot_qrcode?bot_type=3", {
    local_token_list: localTokenList(state),
  });
  const qrcode = data.qrcode;
  const img = data.qrcode_img_content || data.url || "";
  if (!qrcode) throw new Error(`获取二维码失败: ${JSON.stringify(data)}`);
  const now = Date.now();
  updateState((s) => {
    s.pendingQrs = (s.pendingQrs || [])
      .filter((p) => p?.qrcode && now - (p.at || 0) < QR_TTL_MS)
      .slice(-19);
    s.pendingQrs.push({ qrcode, img, at: now });
    return s;
  });
  return {
    qrcode,
    image: img,
    existing_accounts: listAccounts(state).map(accountSummary),
    next: "wechat_login_wait",
    hint: "向用户展示二维码后，立即调用 wechat_login_wait，轮询至 logged_in=true。",
  };
}

export async function loginWait(timeoutMs = 120_000, qrcodeArg) {
  const state = loadState();
  const qrcode = qrcodeArg || state.pendingQrs.at(-1)?.qrcode;
  if (!qrcode) throw new Error("没有进行中的登录，先调用 wechat_login_start");
  const baseUrl = loginBaseUrl();
  const deadline = Date.now() + timeoutMs;
  let last = { status: "wait" };
  while (Date.now() < deadline) {
    const pollStart = Date.now();
    const remaining = deadline - pollStart;
    if (remaining <= 0) break;
    const reqTimeout = Math.min(LONG_POLL_MS + 5_000, Math.max(1_000, remaining));
    try {
      last = await apiGet(
        baseUrl,
        `ilink/bot/get_qrcode_status?qrcode=${encodeURIComponent(qrcode)}`,
        reqTimeout,
      );
    } catch (err) {
      if (err?.name === "AbortError") {
        continue;
      }
      throw err;
    }
    if (last.status === "confirmed" && last.bot_token) {
      let account;
      updateState((s) => {
        s.pendingQrs = s.pendingQrs.filter((p) => p.qrcode !== qrcode);
        account = applyLoginConfirm(s, last);
        return s;
      });
      return {
        logged_in: true,
        account: accountSummary(account),
        ilink_bot_id: account.ilinkBotId,
        ilink_user_id: account.ilinkUserId,
        accounts: listAccounts(loadState()).map(accountSummary),
        hint: "绑定完成。为该号创建专属 Grok Bot 助手，描述为：「负责该微信号的入站私信。收到按 ilink_bot_id 转交的私信后，立刻用同一 ilink_bot_id 向该微信对端回复：先 wechat_typing（on），再 wechat_send 或 wechat_send_media，发完关闭正在输入。」调用 wechat_set_dedicated_assistant 登记 assistant_id 与 assistant_name。后续扫码绑定无需再配 webhook。",
      };
    }
    if (last.status === "binded_redirect" && last.bot_token) {
      let account;
      updateState((s) => {
        s.pendingQrs = s.pendingQrs.filter((p) => p.qrcode !== qrcode);
        account = applyLoginConfirm(s, last);
        return s;
      });
      return {
        logged_in: true,
        redirected: true,
        account: accountSummary(account),
        ilink_bot_id: account.ilinkBotId,
        ilink_user_id: account.ilinkUserId,
        accounts: listAccounts(loadState()).map(accountSummary),
        hint: "绑定完成。为该号创建专属 Grok Bot 助手，描述为：「负责该微信号的入站私信。收到按 ilink_bot_id 转交的私信后，立刻用同一 ilink_bot_id 向该微信对端回复：先 wechat_typing（on），再 wechat_send 或 wechat_send_media，发完关闭正在输入。」调用 wechat_set_dedicated_assistant 登记 assistant_id 与 assistant_name。后续扫码绑定无需再配 webhook。",
      };
    }
    if (last.status === "expired") {
      updateState((s) => {
        s.pendingQrs = s.pendingQrs.filter((p) => p.qrcode !== qrcode);
        return s;
      });
      return { logged_in: false, expired: true, next: "wechat_login_start", hint: "调用 wechat_login_start 取新码，出码后立即 wechat_login_wait" };
    }
    const elapsed = Date.now() - pollStart;
    if (elapsed < MIN_QR_POLL_INTERVAL_MS && Date.now() < deadline) {
      await sleep(Math.min(MIN_QR_POLL_INTERVAL_MS - elapsed, Math.max(0, deadline - Date.now())));
    }
  }
  return { logged_in: false, status: last.status || "wait", next: "wechat_login_wait", hint: "立即再次调用 wechat_login_wait" };
}

export async function notifyStart(account) {
  if (!account?.token) return;
  try {
    await apiPost(account.baseUrl, "ilink/bot/msg/notifystart", {}, account.token, 10_000);
  } catch {
    // 部分环境未开放该接口
  }
}

export async function notifyStop(account) {
  if (!account?.token) return;
  try {
    await apiPost(account.baseUrl, "ilink/bot/msg/notifystop", {}, account.token, 10_000);
  } catch {
    // ignore
  }
}

export async function getUpdates(account, { autoCommitBuf = true, signal } = {}) {
  let data;
  const controller = new AbortController();
  const onAbort = () => controller.abort();
  if (signal) {
    if (signal.aborted) return { ret: 0, msgs: [], session_expired: false, next_updates_buf: null };
    signal.addEventListener("abort", onAbort, { once: true });
  }
  const timer = setTimeout(() => controller.abort(), LONG_POLL_MS + 5_000);
  try {
    const res = await fetch(joinUrl(account.baseUrl, "ilink/bot/getupdates"), {
      method: "POST",
      headers: postHeaders(account.token),
      body: JSON.stringify({ get_updates_buf: account.getUpdatesBuf || "", base_info: baseInfo() }),
      signal: controller.signal,
    });
    const text = await res.text();
    if (!res.ok) throw new Error(`HTTP ${res.status}: ${text.slice(0, 400)}`);
    data = JSON.parse(text);
  } catch (err) {
    if (err?.name === "AbortError") {
      return { ret: 0, msgs: [], session_expired: false, next_updates_buf: null };
    }
    throw err;
  } finally {
    clearTimeout(timer);
    if (signal) signal.removeEventListener("abort", onAbort);
  }
  if (data.errcode === ERR_SESSION_EXPIRED || data.ret === ERR_SESSION_EXPIRED) {
    return { ret: data.ret ?? 0, msgs: [], session_expired: true, next_updates_buf: null };
  }
  if ((data.ret !== undefined && data.ret !== 0) || (data.errcode !== undefined && data.errcode !== 0)) {
    throw new Error(`getupdates ret=${data.ret ?? data.errcode} ${data.errmsg || ""}`.trim());
  }
  const nextBuf = typeof data.get_updates_buf === "string" ? data.get_updates_buf : null;
  if (nextBuf !== null && autoCommitBuf) {
    commitUpdatesBuf(account.token, nextBuf);
    account.getUpdatesBuf = nextBuf;
  }
  return { ...data, session_expired: false, next_updates_buf: nextBuf };
}

function parseAesKey(raw) {
  if (!raw) throw new Error("缺少 aes_key");
  const decoded = Buffer.from(raw, "base64");
  if (decoded.length === 16) return decoded;
  const asText = decoded.toString("utf8");
  if (/^[0-9a-fA-F]{32}$/.test(asText)) return Buffer.from(asText, "hex");
  if (decoded.length === 32 && /^[0-9a-fA-F]+$/.test(decoded.toString("ascii"))) {
    return Buffer.from(decoded.toString("ascii"), "hex");
  }
  throw new Error("无法解析 aes_key");
}

function aesEcb(buffer, key, mode) {
  const cipher = mode === "encrypt"
    ? crypto.createCipheriv("aes-128-ecb", key, null)
    : crypto.createDecipheriv("aes-128-ecb", key, null);
  return Buffer.concat([cipher.update(buffer), cipher.final()]);
}

function paddedSize(n) {
  return Math.ceil((n + 1) / 16) * 16;
}

export async function downloadMedia(media, label) {
  const param = media?.encrypt_query_param || "";
  const fullUrl = media?.full_url || "";
  if (!param && !fullUrl) return null;
  const allowInsecure = process.env.GROK_WECHAT_ALLOW_INSECURE_API === "1";
  const url = fullUrl
    ? assertSafeRemoteUrl(fullUrl, { allowHttp: allowInsecure, allowLoopback: allowInsecure })
    : `${CDN_BASE}/download?encrypted_query_param=${encodeURIComponent(param)}`;
  const { buffer: cipher } = await fetchBufferBounded(url, { method: "GET" }, MEDIA_TIMEOUT_MS, MAX_MEDIA_BYTES);
  const key = parseAesKey(media.aes_key);
  const plain = aesEcb(cipher, key, "decrypt");
  const mediaDir = path.resolve(paths().media);
  fs.mkdirSync(mediaDir, { recursive: true, mode: 0o700 });
  const safeName = safeMediaFilename(label);
  const uniqueName = `${Date.now()}-${crypto.randomBytes(4).toString("hex")}-${safeName}`;
  const file = path.resolve(mediaDir, uniqueName);
  if (!file.startsWith(mediaDir + path.sep)) {
    throw new Error("非法媒体保存路径");
  }
  fs.writeFileSync(file, plain, { mode: 0o600 });
  return file;
}

function itemText(item) {
  if (item?.text_item?.text) return item.text_item.text;
  if (item?.voice_item?.text) return item.voice_item.text;
  if (item?.ref_msg?.title) return `引用: ${item.ref_msg.title}`;
  return "";
}

export async function normalizeInbound(msg) {
  const from = msg.from_user_id || "";
  const items = [];
  let text = "";
  for (const [i, item] of (msg.item_list || []).entries()) {
    const type = item.type;
    const piece = itemText(item);
    if (piece) text = text ? `${text}\n${piece}` : piece;
    if (type === ITEM.IMAGE && item.image_item?.media) {
      const file = await downloadMedia(item.image_item.media, `image-${i}.bin`).catch(() => null);
      items.push({ type: "image", path: file });
    } else if (type === ITEM.FILE && item.file_item) {
      const file = await downloadMedia(item.file_item.media, item.file_item.file_name || `file-${i}`).catch(() => null);
      items.push({ type: "file", name: item.file_item.file_name || "", path: file });
    } else if (type === ITEM.VIDEO && item.video_item?.media) {
      const file = await downloadMedia(item.video_item.media, `video-${i}.bin`).catch(() => null);
      items.push({ type: "video", path: file });
    } else if (type === ITEM.VOICE && item.voice_item) {
      items.push({ type: "voice", text: item.voice_item.text || "", playtime_ms: item.voice_item.playtime });
    } else if (type === ITEM.TEXT) {
      items.push({ type: "text", text: piece });
    }
  }
  return {
    from_user_id: from,
    context_token: msg.context_token || "",
    message_id: msg.message_id ?? msg.client_id ?? "",
    create_time_ms: msg.create_time_ms,
    text,
    items,
  };
}

export async function collectInbound(rawMsgs, account, { enforceAllowlist = true } = {}) {
  const out = [];
  const stateSnapshot = enforceAllowlist ? loadState() : null;
  for (const msg of rawMsgs || []) {
    if (msg.message_type && msg.message_type !== MSG_TYPE.USER) continue;
    if (msg.message_state && msg.message_state !== MSG_STATE.FINISH) continue;
    const fromUserId = msg.from_user_id || "";
    if (!fromUserId) continue;
    if (enforceAllowlist && !isAllowed(stateSnapshot, fromUserId)) continue;
    const normalized = await normalizeInbound(msg);
    if (!normalized.from_user_id) continue;
    updateState((s) => {
      const hit = findAccount(s, { token: account.token });
      if (hit) rememberContext(s, hit, normalized.from_user_id, normalized.context_token);
      return s;
    });
    out.push({
      ...normalized,
      ilink_bot_id: account.ilinkBotId,
      ilink_user_id: account.ilinkUserId,
    });
  }
  return { messages: out, logged_in_user: account.ilinkUserId };
}

export function toWeChatText(markdown) {
  const raw = String(markdown ?? "");
  if (!raw.trim()) return "";
  const stash = [];
  const hold = (val) => {
    const id = `\x00WC${stash.length}\x00`;
    stash.push(val);
    return id;
  };
  let out = raw
    .replace(/```[\s\S]*?```/g, (block) => hold(block.replace(/^```\w*\r?\n?|```$/g, "").trim()))
    .replace(/`([^`\r\n]+)`/g, (_, code) => hold(code))
    .replace(/\[([^\]]+)\]\(([^)]+)\)/g, (_, label, url) => `${label} ${hold(url)}`)
    .replace(/https?:\/\/[^\s)]+/g, (url) => hold(url))
    .replace(/\*\*([^*]+)\*\*/g, "$1")
    .replace(/(^|[^*])\*([^*\r\n]+)\*(?!\*)/g, "$1$2")
    .replace(/^#{1,6}\s+/gm, "")
    .replace(/^\s*[-*+]\s+/gm, "• ")
    .replace(/\x00WC(\d+)\x00/g, (_, idx) => stash[Number(idx)] ?? "")
    .trim();
  return out || raw.trim();
}

export function splitWeChatChunks(text, maxUnits = 4000) {
  const chunks = [];
  let i = 0;
  while (i < text.length) {
    let end = Math.min(i + maxUnits, text.length);
    if (end < text.length) {
      const code = text.charCodeAt(end - 1);
      if (code >= 0xd800 && code <= 0xdbff && end > i + 1) {
        end -= 1;
      }
    }
    chunks.push(text.slice(i, end));
    i = end;
  }
  return chunks;
}

async function sendItem(account, to, item, contextToken) {
  const token = contextToken || contextFor(account, to);
  const body = {
    msg: {
      from_user_id: "",
      to_user_id: to,
      client_id: clientId(),
      message_type: MSG_TYPE.BOT,
      message_state: MSG_STATE.FINISH,
      item_list: [item],
      context_token: token || undefined,
    },
  };
  const resp = await apiPost(account.baseUrl, "ilink/bot/sendmessage", body, account.token);
  if (resp.ret && resp.ret !== 0) {
    throw new Error(`发送失败 ret=${resp.ret} ${resp.errmsg || ""}`);
  }
  return {
    to_user_id: to,
    ilink_bot_id: account.ilinkBotId,
    ilink_user_id: account.ilinkUserId,
    context_token: token || "",
    ret: resp.ret ?? 0,
  };
}

export async function sendText(toUserId, text, ilinkBotId) {
  const state = loadState();
  const account = resolveAccountForPeer(state, { to_user_id: toUserId, ilink_bot_id: ilinkBotId });
  const to = toUserId;
  const token = contextFor(account, to);
  if (!token) {
    throw new Error("还没有该用户的 context_token。对方需要先从微信给你发一条消息，会话通道才会建立");
  }
  const plain = toWeChatText(text);
  if (!plain) throw new Error("发送内容为空");
  const chunks = splitWeChatChunks(plain, 4000);
  let last;
  for (const chunk of chunks) {
    last = await sendItem(account, to, { type: ITEM.TEXT, text_item: { text: chunk } }, token);
  }
  return last;
}

async function uploadFile(account, to, realFilePath, mediaType) {
  const raw = fs.readFileSync(realFilePath);
  const rawMd5 = crypto.createHash("md5").update(raw).digest("hex");
  const aesKey = crypto.randomBytes(16);
  const aesKeyHex = aesKey.toString("hex");
  const cipher = aesEcb(raw, aesKey, "encrypt");
  const filekey = crypto.randomBytes(16).toString("hex");
  const upload = await apiPost(
    account.baseUrl,
    "ilink/bot/getuploadurl",
    {
      filekey,
      media_type: mediaType,
      to_user_id: to,
      rawsize: raw.length,
      rawfilemd5: rawMd5,
      filesize: paddedSize(raw.length),
      no_need_thumb: true,
      aeskey: aesKeyHex,
    },
    account.token,
  );
  if (upload.ret && upload.ret !== 0) {
    throw new Error(`获取上传地址失败 ret=${upload.ret} ${upload.errmsg || ""}`.trim());
  }
  if (!upload.upload_full_url && !upload.upload_param) {
    throw new Error("获取上传地址失败：缺少 upload_full_url / upload_param");
  }
  const allowInsecure = process.env.GROK_WECHAT_ALLOW_INSECURE_API === "1";
  const uploadUrl = upload.upload_full_url
    ? assertSafeRemoteUrl(upload.upload_full_url, { allowHttp: allowInsecure, allowLoopback: allowInsecure })
    : `${CDN_BASE}/upload?encrypted_query_param=${encodeURIComponent(upload.upload_param)}&filekey=${encodeURIComponent(filekey)}`;

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), MEDIA_TIMEOUT_MS);
  let res;
  try {
    res = await fetch(uploadUrl, {
      method: "POST",
      headers: { "Content-Type": "application/octet-stream" },
      body: cipher,
      signal: controller.signal,
    });
  } finally {
    clearTimeout(timer);
  }
  if (!res.ok) throw new Error(`CDN 上传失败 ${res.status}`);
  const downloadParam = res.headers.get("x-encrypted-param") || "";
  if (!downloadParam) throw new Error("CDN 响应缺少 x-encrypted-param");
  return {
    filekey,
    fileSize: raw.length,
    fileSizeCiphertext: cipher.length,
    aeskeyHex: aesKeyHex,
    downloadEncryptedQueryParam: downloadParam,
  };
}

function mediaRef(uploaded) {
  return {
    encrypt_query_param: uploaded.downloadEncryptedQueryParam,
    aes_key: Buffer.from(uploaded.aeskeyHex).toString("base64"),
    encrypt_type: 1,
  };
}

export async function sendMedia(toUserId, filePath, kind, caption, ilinkBotId) {
  const state = loadState();
  const account = resolveAccountForPeer(state, { to_user_id: toUserId, ilink_bot_id: ilinkBotId });
  const to = toUserId;
  const token = contextFor(account, to);
  if (!token) throw new Error("还没有该用户的 context_token，需对方先发一条微信");
  const typeMap = { image: UPLOAD.IMAGE, video: UPLOAD.VIDEO, file: UPLOAD.FILE };
  const mediaType = typeMap[kind];
  if (!mediaType) throw new Error("kind 只能是 image / video / file");
  const { realPath } = assertSafeOutboundMediaPath(filePath);
  const uploaded = await uploadFile(account, to, realPath, mediaType);
  if (caption) await sendText(to, caption, account.ilinkBotId);
  const media = mediaRef(uploaded);
  if (kind === "image") {
    return sendItem(account, to, { type: ITEM.IMAGE, image_item: { media, mid_size: uploaded.fileSizeCiphertext } }, token);
  }
  if (kind === "video") {
    return sendItem(account, to, { type: ITEM.VIDEO, video_item: { media, video_size: uploaded.fileSizeCiphertext } }, token);
  }
  return sendItem(account, to, {
    type: ITEM.FILE,
    file_item: { media, file_name: path.basename(filePath), len: String(uploaded.fileSize) },
  }, token);
}

async function fetchFreshTypingTicket(account, to) {
  const cfg = await apiPost(
    account.baseUrl,
    "ilink/bot/getconfig",
    { ilink_user_id: to, context_token: contextFor(account, to) || undefined },
    account.token,
    10_000,
  );
  const ticket = cfg.typing_ticket || "";
  if (ticket) {
    updateState((s) => {
      const hit = findAccount(s, { token: account.token });
      if (hit) hit.typingTickets[to] = { ticket, at: Date.now() };
      return s;
    });
  }
  return ticket;
}

export async function setTyping(toUserId, on, ilinkBotId) {
  const state = loadState();
  const account = resolveAccountForPeer(state, { to_user_id: toUserId, ilink_bot_id: ilinkBotId });
  const to = toUserId;
  let ticket = account.typingTickets?.[to]?.ticket;
  const age = Date.now() - (account.typingTickets?.[to]?.at || 0);
  let usedCached = Boolean(ticket && age <= 20 * 60 * 60 * 1000);
  if (!usedCached) {
    ticket = await fetchFreshTypingTicket(account, to);
  }
  if (!ticket) throw new Error("未拿到 typing_ticket");
  let resp = await apiPost(
    account.baseUrl,
    "ilink/bot/sendtyping",
    { ilink_user_id: to, typing_ticket: ticket, status: on ? TYPING.ON : TYPING.OFF },
    account.token,
    10_000,
  );
  if (resp.ret && resp.ret !== 0 && usedCached) {
    updateState((s) => {
      const hit = findAccount(s, { token: account.token });
      if (hit?.typingTickets) delete hit.typingTickets[to];
      return s;
    });
    ticket = await fetchFreshTypingTicket(account, to);
    if (!ticket) throw new Error(`sendtyping 失败 ret=${resp.ret}`);
    resp = await apiPost(
      account.baseUrl,
      "ilink/bot/sendtyping",
      { ilink_user_id: to, typing_ticket: ticket, status: on ? TYPING.ON : TYPING.OFF },
      account.token,
      10_000,
    );
  }
  if (resp.ret && resp.ret !== 0) {
    throw new Error(`sendtyping 失败 ret=${resp.ret} ${resp.errmsg || ""}`.trim());
  }
  return { to_user_id: to, ilink_bot_id: account.ilinkBotId, typing: !!on };
}

export function statusPayload() {
  const state = loadState();
  const accounts = listAccounts(state);
  return {
    logged_in: accounts.length > 0,
    account_count: accounts.length,
    global_wake_configured: hasGlobalWake(),
    accounts: accounts.map((a) => ({
      ...accountSummary(a),
      peers: Object.keys(a.contextTokens || {}),
    })),
    pending_qr_count: state.pendingQrs.length,
    allow_from: state.allowFrom,
    inbox: peekInboxCount(),
  };
}

export function validateWakeUrl(url) {
  const allowLocal = process.env.GROK_WECHAT_ALLOW_LOCAL_WAKE === "1";
  return assertSafeRemoteUrl(url, { allowHttp: true, allowLoopback: allowLocal });
}

export async function postWakeRequest(url, key, payload, timeoutMs = WAKE_TIMEOUT_MS) {
  const safeUrl = validateWakeUrl(url);
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(safeUrl, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${key}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(payload),
      signal: controller.signal,
    });
    const text = await res.text();
    return { status: res.status, ok: res.ok, body: text.slice(0, 180) };
  } finally {
    clearTimeout(timer);
  }
}

export async function probeWake(url, key) {
  const { status } = await postWakeRequest(url, key, {
    source: "grok-wechat",
    probe: true,
    count: 0,
  });
  return { status };
}

export async function setAccountWake(ilink_bot_id, url, key) {
  if (!url || !key) throw new Error("url 和 key 必填");
  const safeUrl = validateWakeUrl(url);
  const probe = await probeWake(safeUrl, key);
  saveGlobalWake(safeUrl, key);
  if (ilink_bot_id) {
    updateState((s) => {
      const hit = findAccount(s, { ilink_bot_id });
      if (hit) hit.wake = { url: safeUrl, key };
      return s;
    });
  }
  saveStateSecure(loadState());
  return {
    global_wake_configured: true,
    ilink_bot_id: ilink_bot_id || null,
    probe,
    accounts: listAccounts(loadState()).map(accountSummary),
  };
}

export function setDedicatedAssistant(ilink_bot_id, assistant_id, assistant_name) {
  if (!ilink_bot_id) throw new Error("ilink_bot_id 必填");
  if (!assistant_name) throw new Error("assistant_name 必填");
  updateState((s) => {
    const hit = requireAccount(s, { ilink_bot_id });
    hit.dedicatedAssistant = {
      id: assistant_id || hit.dedicatedAssistant?.id || "",
      name: assistant_name,
    };
    return s;
  });
  saveStateSecure(loadState());
  const account = findAccount(loadState(), { ilink_bot_id });
  return accountSummary(account);
}
