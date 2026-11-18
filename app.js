/**
 * CipherLoom — Anna App bundle (static SPA).
 *
 * Host integration surface (AnnaAppRuntime SDK):
 *   anna.storage.*            vault index (KV)
 *   anna.files.upload_*       ciphertext blobs -> R2
 *   anna.tools.invoke         -> CipherLoom Executa (encrypt/decrypt/ask/...)
 *   anna.llm.complete         answer synthesis from retrieved excerpts
 *   anna.window.* / anna.on   title, close, entry_payload protocol
 */
import { AnnaAppRuntime } from "/static/anna-apps/_sdk/latest/index.js";

// Replace after minting at https://anna.partners/executa (see README)
const TOOL_ID = "tool-dev-cipherloom-CHANGEME0";

const anna = await AnnaAppRuntime.connect();

// --------------------------------------------------------------- theme & dom
document.documentElement.dataset.theme = anna.theme ?? "dark";
anna.onThemeChange(({ theme }) => { document.documentElement.dataset.theme = theme; });

const $ = (id) => document.getElementById(id);
const setStatus = (t) => { $("status").textContent = t; };

let vaultKey = null;          // passphrase held in memory only (Lock clears it)
let index = [];               // [{id, name, size, tags, ct_b64, nonce_b64, sha256, cid_like, created}]

// ------------------------------------------------------------ storage helpers
async function loadIndex() {
  const r = await anna.storage.get({ key: "vault.index" });
  index = (r?.ok && r.result?.value) || [];
}
async function saveIndex() {
  await anna.storage.set({ key: "vault.index", value: index });
}

// ------------------------------------------------------------- executa calls
/**
 * Invoke the CipherLoom Executa and unwrap its {success, data} envelope.
 * Nesting tolerance: host may return {ok, result:{success,data}} or
 * {ok, result:{result:{success,data}}} depending on dispatcher pass-through.
 */
async function invoke(action, args = {}) {
  const r = await anna.tools.invoke({ tool_id: TOOL_ID, method: "cipherloom", args: { action, ...args } });
  if (!r?.ok) throw new Error(r?.error?.message || "invoke failed");
  const payload = r.result?.result ?? r.result ?? r;
  if (payload?.success === false) throw new Error(payload?.error || "plugin returned success=false");
  return payload?.data ?? payload;
}

// --------------------------------------------------------------------- unlock
function ensureKey() {
  if (vaultKey) return vaultKey;
  const k = prompt("Vault passphrase (kept in memory only; Lock clears it):");
  if (!k) throw new Error("cancelled");
  vaultKey = k;
  $("btn-relock").hidden = false;
  return vaultKey;
}
$("btn-relock").addEventListener("click", () => {
  vaultKey = null;
  $("btn-relock").hidden = true;
  setStatus("Vault locked.");
});

// ------------------------------------------------------------------- encrypt
async function encryptFiles(files) {
  const key = ensureKey();
  for (const f of files) {
    const text = await f.text();
    setStatus(`Encrypting ${f.name}…`);
    const blob = await invoke("encrypt", { plaintext: text, passphrase: key });
    const rec = {
      id: crypto.randomUUID(),
      name: f.name,
      size: f.size,
      tags: [],
      ct_b64: blob.ct_b64,
      nonce_b64: blob.nonce_b64,
      sha256: blob.sha256,
      cid_like: blob.cid_like,
      created: Date.now(),
    };
    // Persist ciphertext blob to APS files (content-addressed path).
    try {
      const path = `cipherloom/${rec.cid_like}.bin`;
      const init = await anna.files.upload_init({
        path, content_type: "application/octet-stream", size: rec.ct_b64.length,
      });
      if (init?.ok) {
        await fetch(init.result.put_url, { method: "PUT", body: rec.ct_b64 });
        await anna.files.upload_finalize({ path, size: init.result.size ?? rec.ct_b64.length });
        rec.file_path = path;
      }
    } catch (err) {
      console.warn("blob upload skipped:", err);  // index still holds the ciphertext
    }
    index.unshift(rec);
    await saveIndex();
  }
  renderGrid();
  setStatus(`Encrypted ${files.length} file(s). Ciphertext only at rest.`);
}

$("btn-add").addEventListener("click", () => $("file-input").click());
$("file-input").addEventListener("change", (e) => {
  if (e.target.files?.length) encryptFiles([...e.target.files]);
  e.target.value = "";
});

// ----------------------------------------------------------------------- ask
async function askQuestion(q) {
  const key = ensureKey();
  $("answer").hidden = false;
  $("a-body").textContent = "Retrieving…";
  $("a-cites").textContent = "";
  $("a-run").textContent = "";

  // 1) retrieve grounded excerpts across stored files (MVP: up to 20 newest)
  const all = [];
  for (const rec of index.slice(0, 20)) {
    try {
      const r = await invoke("ask", {
        ciphertext: rec.ct_b64, nonce_b64: rec.nonce_b64, passphrase: key, question: q,
      });
      (r.excerpts || []).forEach(x => all.push({ ...x, file: rec.name }));
    } catch (err) {
      console.warn("ask failed for", rec.name, err);
    }
  }
  if (!all.length) {
    $("a-body").textContent = "No matching content. Unlock the vault and add files first.";
    return;
  }
  all.sort((a, b) => b.score - a.score);
  const top = all.slice(0, 6);

  // 2) synthesise with the platform LLM (user's own quota/BYOK)
  const context = top.map(x => `[Excerpt ${x.idx} · ${x.file}]\n${x.text}`).join("\n\n");
  const reply = await anna.llm.complete({
    messages: [
      { role: "system", content: { type: "text",
        text: "You are CipherLoom. Answer ONLY from the provided decrypted excerpts. Cite excerpt ids inline. If insufficient, say so." } },
      { role: "user", content: { type: "text", text: `Question: ${q}\n\nExcerpts:\n${context}` } },
    ],
    maxTokens: 700,
  });

  $("a-body").textContent = reply?.content?.text ?? "(no answer)";
  $("a-cites").textContent = "Sources: " + top.map(x => `[E${x.idx}] ${x.file}`).join("  ");
  $("a-run").textContent = `✓ Qualified App Run — ${top.length} excerpts · ${reply?.usage?.totalTokens ?? "?"} tokens`;

  // 3) provenance: log the run (feeds your MAU dashboard)
  const prev = await anna.storage.get({ key: "vault.runs" });
  const runs = (prev?.ok && prev.result?.value) || [];
  runs.unshift({ q, at: Date.now(), excerpts: top.length });
  await anna.storage.set({ key: "vault.runs", value: runs.slice(0, 500) });
  setStatus("Answer ready — run logged.");
}

$("ask-btn").addEventListener("click", () => {
  const q = $("ask-input").value.trim();
  if (q) askQuestion(q);
});
$("ask-input").addEventListener("keydown", (e) => { if (e.key === "Enter") $("ask-btn").click(); });

// ------------------------------------------------------------------ rendering
function renderGrid() {
  const filter = $("search").value.trim().toLowerCase();
  const rows = index.filter(r => !filter || r.name.toLowerCase().includes(filter));
  $("empty").hidden = index.length > 0;
  $("stat").textContent = `${index.length} file(s)`;
  $("grid").innerHTML = rows.map(r => `
    <button class="card" data-id="${r.id}">
      <div class="card-name">${escapeHtml(r.name)}</div>
      <div class="card-meta">${fmtSize(r.size)} · ${(r.tags || []).join(", ") || "untagged"}</div>
      <div class="card-cid">${r.cid_like ? r.cid_like.slice(0, 16) + "…" : "—"}</div>
    </button>`).join("");
  $("grid").querySelectorAll(".card").forEach(el =>
    el.addEventListener("click", () => showDetail(el.dataset.id)));
}

async function showDetail(id) {
  const rec = index.find(x => x.id === id);
  if (!rec) return;
  $("detail").hidden = false;
  $("d-title").textContent = rec.name;
  $("d-meta").textContent =
    `SHA-256 ${rec.sha256 ? rec.sha256.slice(0, 24) + "…" : "—"} · CID ${rec.cid_like} · ${fmtSize(rec.size)}`;
  try {
    const key = ensureKey();
    const res = await invoke("decrypt", {
      ciphertext: rec.ct_b64, nonce_b64: rec.nonce_b64, passphrase: key,
    });
    $("d-body").textContent = res.plaintext.slice(0, 4000);
  } catch (err) {
    $("d-body").textContent = "Decrypt failed: " + err.message;
  }
}
$("search").addEventListener("input", renderGrid);

// ------------------------------------------------------- entry_payload protocol
function applyPayload(p) {
  if (!p) return;
  if (p.action === "ask" && p.q) { $("ask-input").value = p.q; askQuestion(p.q); }
}
anna.on("entry_payload", applyPayload);

// ------------------------------------------------------------------------ boot
// Build escape table via char codes to avoid quote-escaping pitfalls.
const ESCAPES = { 38: "&", 60: "<", 62: ">", 34: String.fromCharCode(34), 39: String.fromCharCode(39) };
function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ESCAPES[c.charCodeAt(0)] ?? c);
}
function fmtSize(n) {
  return n > 1048576 ? (n / 1048576).toFixed(1) + " MB" : Math.max(1, Math.round(n / 1024)) + " KB";
}

await loadIndex();
renderGrid();
await anna.window.set_title({ title: "CipherLoom Vault" });
await anna.storage.set({ key: "bootedOnce", value: true });
applyPayload(anna.entryPayload);
setStatus(anna.runtimeState?.bootedOnce
  ? `Vault resumed — ${index.length} file(s).`
  : "Ready. Encrypt a file to start.");