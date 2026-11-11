import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  appendInbox,
  clearPid,
  commitUpdatesBuf,
  drainInbox,
  loadState,
  paths,
  readPid,
  saveGlobalWake,
  updateState,
  upsertAccount,
  writePid,
} from "./store.js";
import {
  ITEM,
  MSG_STATE,
  MSG_TYPE,
  assertSafeOutboundMediaPath,
  assertSafeRemoteUrl,
  collectInbound,
  downloadMedia,
  loginStart,
  loginWait,
  safeMediaFilename,
  sendMedia,
  setTyping,
  splitWeChatChunks,
  toWeChatText,
  validateWakeUrl,
} from "./ilink.js";
import { connectorAbandoned, stripAutostartFromFile } from "./uninstall.js";
import { extractFrames, formatRpcFrame, onRpc } from "./index.js";

function withTempHome(fn) {
  const prev = process.env.GROK_WECHAT_HOME;
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "grok-wechat-test-"));
  process.env.GROK_WECHAT_HOME = dir;
  return Promise.resolve()
    .then(() => fn(dir))
    .finally(() => {
      if (prev === undefined) delete process.env.GROK_WECHAT_HOME;
      else process.env.GROK_WECHAT_HOME = prev;
      fs.rmSync(dir, { recursive: true, force: true });
    });
}

function encryptAes128Ecb(plain, keyBuf) {
  const cipher = crypto.createCipheriv("aes-128-ecb", keyBuf, null);
  return Buffer.concat([cipher.update(plain), cipher.final()]);
}

test("inbound file path traversal is neutralized and stays inside media dir", async () => {
  await withTempHome(async (home) => {
    const outsideTarget = path.join(home, "escaped-bashrc");
    const relEscape = `/../../../../${outsideTarget.replace(/^\/+/, "")}`;

    assert.equal(safeMediaFilename(relEscape), "escaped-bashrc");
    assert.equal(safeMediaFilename("../../.bashrc"), "bashrc");
    assert.equal(safeMediaFilename("..\\..\\evil.sh"), "evil.sh");

    const key = crypto.randomBytes(16);
    const payload = Buffer.from("hello media", "utf8");
    const encrypted = encryptAes128Ecb(payload, key);

    const origFetch = globalThis.fetch;
    globalThis.fetch = async () =>
      new Response(encrypted, { status: 200, headers: { "content-length": String(encrypted.length) } });
    try {
      const saved = await downloadMedia(
        { encrypt_query_param: "abc", aes_key: key.toString("base64") },
        relEscape,
      );
      assert.ok(saved.startsWith(path.resolve(paths().media) + path.sep));
      assert.equal(fs.existsSync(outsideTarget), false);
      assert.deepEqual(fs.readFileSync(saved), payload);
      const mode = fs.statSync(saved).mode & 0o777;
      assert.equal(mode, 0o600);
    } finally {
      globalThis.fetch = origFetch;
    }
  });
});

test("collectInbound enforces allowFrom BEFORE downloading media or storing context", async () => {
  await withTempHome(async () => {
    updateState((s) => {
      s.allowFrom = ["approved_user"];
      upsertAccount(s, { token: "tok1", ilinkBotId: "bot1", ilinkUserId: "u1" });
      return s;
    });

    let cdnHits = 0;
    const origFetch = globalThis.fetch;
    globalThis.fetch = async () => {
      cdnHits += 1;
      throw new Error("CDN should not be called for blocked sender");
    };
    try {
      const account = loadState().accounts[0];
      const res = await collectInbound(
        [
          {
            from_user_id: "stranger_user",
            message_type: MSG_TYPE.USER,
            message_state: MSG_STATE.FINISH,
            context_token: "ctx_stranger",
            item_list: [
              {
                type: ITEM.FILE,
                file_item: {
                  file_name: "doc.pdf",
                  media: { encrypt_query_param: "p", aes_key: crypto.randomBytes(16).toString("base64") },
                },
              },
            ],
          },
        ],
        account,
      );
      assert.equal(res.messages.length, 0);
      assert.equal(cdnHits, 0);
      assert.equal(loadState().accounts[0].contextTokens.stranger_user, undefined);
    } finally {
      globalThis.fetch = origFetch;
    }
  });
});

test("assertSafeOutboundMediaPath blocks credentials, symlinks, and directories", async () => {
  await withTempHome(async (home) => {
    updateState((s) => {
      upsertAccount(s, { token: "secret", ilinkBotId: "b1", contextTokens: { peer1: { token: "ctx1", at: 1 } } });
      return s;
    });
    saveGlobalWake("https://example.com/wake", "secret-key");

    const workDir = fs.mkdtempSync(path.join(os.tmpdir(), "grok-wechat-work-"));
    try {
      const okFile = path.join(workDir, "chart.png");
      fs.writeFileSync(okFile, "png-bytes");
      assert.equal(assertSafeOutboundMediaPath(okFile).size, 9);

      const inboundMedia = path.join(paths().media, "inbound.bin");
      fs.writeFileSync(inboundMedia, "inbound");
      assert.equal(assertSafeOutboundMediaPath(inboundMedia).size, 7);

      // Direct credential files blocked
      assert.throws(() => assertSafeOutboundMediaPath(paths().state), /禁止发送/);
      assert.throws(() => assertSafeOutboundMediaPath(path.join(home, "wake.json")), /禁止发送/);

      // Symlink to credential file blocked
      const symlinkAttack = path.join(workDir, "innocent.txt");
      fs.symlinkSync(paths().state, symlinkAttack);
      assert.throws(() => assertSafeOutboundMediaPath(symlinkAttack), /禁止发送/);

      // .env and .ssh blocked
      const envFile = path.join(workDir, ".env");
      fs.writeFileSync(envFile, "API_KEY=1");
      assert.throws(() => assertSafeOutboundMediaPath(envFile), /禁止发送/);

      // Directory blocked before caption could be sent
      let networkCalls = 0;
      const origFetch = globalThis.fetch;
      globalThis.fetch = async () => {
        networkCalls += 1;
        return new Response("{}", { status: 200 });
      };
      try {
        await assert.rejects(
          () => sendMedia("peer1", workDir, "file", "caption should not send", "b1"),
          /不是普通文件/,
        );
        assert.equal(networkCalls, 0);
      } finally {
        globalThis.fetch = origFetch;
      }
    } finally {
      fs.rmSync(workDir, { recursive: true, force: true });
    }
  });
});

test("SSRF protections reject loopback, private IPs, metadata, and file URLs", () => {
  assert.throws(() => assertSafeRemoteUrl("file:///etc/passwd"), /协议/);
  assert.throws(() => assertSafeRemoteUrl("http://169.254.169.254/latest/meta-data/"), /协议|元数据|私有/);
  assert.throws(() => validateWakeUrl("http://169.254.169.254/latest/meta-data/"), /元数据/);
  assert.throws(() => validateWakeUrl("http://127.0.0.1:8080/hook"), /私有/);
  assert.throws(() => validateWakeUrl("http://[::1]:8080/hook"), /私有/);
  assert.throws(() => validateWakeUrl("http://[::ffff:127.0.0.1]:8080/hook"), /私有/);
  assert.throws(() => validateWakeUrl("http://localhost:3000/hook"), /内网/);
  assert.throws(() => validateWakeUrl("http://10.0.0.5/hook"), /私有/);
  assert.equal(validateWakeUrl("https://hooks.example.com/routine/123"), "https://hooks.example.com/routine/123");
});

test("state permissions stay 0600, corrupt state is backed up, and re-login preserves metadata", async () => {
  await withTempHome(async (home) => {
    updateState((s) => {
      upsertAccount(s, {
        token: "old_tok",
        ilinkBotId: "bot_a",
        ilinkUserId: "user_a",
        contextTokens: { friend1: { token: "ctx_1", at: 100 } },
        dedicatedAssistant: { id: "asst_1", name: "微信1" },
        wake: { url: "https://hooks.example.com/w", key: "k" },
      });
      return s;
    });

    assert.equal(fs.statSync(home).mode & 0o777, 0o700);
    assert.equal(fs.statSync(paths().state).mode & 0o777, 0o600);

    commitUpdatesBuf("old_tok", "cursor_2");
    assert.equal(fs.statSync(paths().state).mode & 0o777, 0o600);

    // Re-login with new token on same ilinkBotId preserves contextTokens & dedicatedAssistant
    const origFetch = globalThis.fetch;
    globalThis.fetch = async (url) => {
      const u = String(url);
      if (u.includes("get_bot_qrcode")) {
        return new Response(JSON.stringify({ qrcode: "qr_rebind", qrcode_img_content: "img" }), { status: 200 });
      }
      if (u.includes("get_qrcode_status")) {
        return new Response(
          JSON.stringify({
            status: "confirmed",
            bot_token: "new_tok",
            ilink_bot_id: "bot_a",
            ilink_user_id: "user_a",
          }),
          { status: 200 },
        );
      }
      throw new Error(`unexpected ${u}`);
    };
    try {
      await loginStart();
      const res = await loginWait(5_000, "qr_rebind");
      assert.equal(res.logged_in, true);
      const acc = loadState().accounts[0];
      assert.equal(acc.token, "new_tok");
      assert.equal(acc.contextTokens.friend1?.token, "ctx_1");
      assert.equal(acc.dedicatedAssistant?.name, "微信1");
      assert.equal(acc.wake?.key, "k");
    } finally {
      globalThis.fetch = origFetch;
    }

    // Corrupt state file is backed up rather than silently lost
    fs.writeFileSync(paths().state, "{broken json", { mode: 0o600 });
    const recovered = loadState();
    assert.deepEqual(recovered.accounts, []);
    const backups = fs.readdirSync(home).filter((f) => f.startsWith("account.json.corrupt."));
    assert.equal(backups.length, 1);
  });
});

test("atomic inbox and expected-PID clearPid prevent races", async () => {
  await withTempHome(async () => {
    appendInbox([{ id: 1, text: "a" }, { id: 2, text: "b" }]);
    appendInbox([{ id: 3, text: "c" }]);
    const drained = drainInbox();
    assert.equal(drained.length, 3);
    assert.deepEqual(drainInbox(), []);

    writePid(11111);
    clearPid(22222);
    assert.equal(readPid(), 11111);
    clearPid(11111);
    assert.equal(readPid(), 0);
  });
});

test("MCP framing handles split Content-Length headers, UTF-8 chunks, and matching output modes", async () => {
  const payloadObj = { jsonrpc: "2.0", id: 7, method: "ping", note: "你好😀世界" };
  const lspWire = Buffer.from(formatRpcFrame(payloadObj, "lsp"), "utf8");

  // Feed 5 bytes at a time to split both the Content-Length header and multi-byte UTF-8 chars
  let acc = Buffer.alloc(0);
  const collected = [];
  for (let i = 0; i < lspWire.length; i += 5) {
    acc = Buffer.concat([acc, lspWire.slice(i, i + 5)]);
    const { frames, rest } = extractFrames(acc);
    acc = rest;
    collected.push(...frames);
  }
  assert.equal(acc.length, 0);
  assert.equal(collected.length, 1);
  assert.equal(collected[0].mode, "lsp");
  assert.deepEqual(JSON.parse(collected[0].body), payloadObj);

  const jsonlWire = Buffer.from(formatRpcFrame(payloadObj, "jsonl"), "utf8");
  const parsedJsonl = extractFrames(jsonlWire);
  assert.equal(parsedJsonl.frames.length, 1);
  assert.equal(parsedJsonl.frames[0].mode, "jsonl");

  const pong = await onRpc({ jsonrpc: "2.0", id: 99, method: "ping" });
  assert.deepEqual(pong, { jsonrpc: "2.0", id: 99, result: {} });
});

test("loginWait throttles fast non-terminal status responses and setTyping refreshes stale tickets", async () => {
  await withTempHome(async () => {
    updateState((s) => {
      s.pendingQrs = [{ qrcode: "qr1", img: "", at: Date.now() }];
      upsertAccount(s, {
        token: "t1",
        ilinkBotId: "b1",
        ilinkUserId: "u1",
        contextTokens: { peer1: { token: "ctx1", at: Date.now() } },
        typingTickets: { peer1: { ticket: "stale_ticket", at: Date.now() } },
      });
      return s;
    });

    let qrPolls = 0;
    let sendTypingCalls = 0;
    const origFetch = globalThis.fetch;
    globalThis.fetch = async (url, init) => {
      const u = String(url);
      if (u.includes("get_qrcode_status")) {
        qrPolls += 1;
        if (qrPolls < 2) {
          return new Response(JSON.stringify({ status: "scaned" }), { status: 200 });
        }
        return new Response(
          JSON.stringify({ status: "confirmed", bot_token: "t_new", ilink_bot_id: "b1", ilink_user_id: "u1" }),
          { status: 200 },
        );
      }
      if (u.includes("sendtyping")) {
        sendTypingCalls += 1;
        const body = JSON.parse(init.body);
        if (body.typing_ticket === "stale_ticket") {
          return new Response(JSON.stringify({ ret: -1, errmsg: "expired ticket" }), { status: 200 });
        }
        return new Response(JSON.stringify({ ret: 0 }), { status: 200 });
      }
      if (u.includes("getconfig")) {
        return new Response(JSON.stringify({ ret: 0, typing_ticket: "fresh_ticket" }), { status: 200 });
      }
      throw new Error(`unexpected ${u}`);
    };
    try {
      const t0 = Date.now();
      const loginRes = await loginWait(10_000, "qr1");
      const elapsed = Date.now() - t0;
      assert.equal(loginRes.logged_in, true);
      assert.equal(qrPolls, 2);
      assert.ok(elapsed >= 1_400, `expected throttle sleep >=1400ms, got ${elapsed}ms`);

      const typingRes = await setTyping("peer1", true, "b1");
      assert.equal(typingRes.typing, true);
      assert.equal(sendTypingCalls, 2);
      assert.equal(loadState().accounts[0].typingTickets.peer1.ticket, "fresh_ticket");
    } finally {
      globalThis.fetch = origFetch;
    }
  });
});

test("toWeChatText preserves code & URLs, splitWeChatChunks preserves emojis, uninstall preserves empty profile", () => {
  const md = "Hello **world**!\n```py\n# comment\nx = *a * *b\n```\nLink: [doc](https://example.com/a*b*c)";
  const plain = toWeChatText(md);
  assert.ok(plain.includes("# comment"));
  assert.ok(plain.includes("x = *a * *b"));
  assert.ok(plain.includes("https://example.com/a*b*c"));
  assert.ok(!plain.includes("**world**"));

  assert.equal(toWeChatText("***"), "***");

  // Emoji surrogate pair right at chunk boundary 3999..4000
  const emojiText = "a".repeat(3999) + "😀" + "b".repeat(10);
  const chunks = splitWeChatChunks(emojiText, 4000);
  assert.equal(chunks.length, 2);
  assert.equal(chunks[0].length, 3999);
  assert.ok(chunks[1].startsWith("😀"));
  assert.equal(chunks.join(""), emojiText);

  // Auto-abandon self-destruct stays disabled & profile file is not unlinked
  assert.equal(connectorAbandoned(), false);
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "grok-wechat-prof-"));
  try {
    const bashrc = path.join(tmpDir, ".bashrc");
    fs.writeFileSync(bashrc, "/home/box/.grok-wechat/ensure-monitor.sh\n");
    assert.equal(stripAutostartFromFile(bashrc), true);
    assert.equal(fs.existsSync(bashrc), true);
    assert.equal(fs.readFileSync(bashrc, "utf8"), "");
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});
