/**
 * Bundle smoke test — drives the SPA through the production dispatcher
 * (no browser, no SSE). Run:  pnpm test  (vitest)
 *
 * Requires @anna-ai/cli as devDependency.
 */
import { describe, it, expect } from "vitest";
import { mountBundle } from "@anna-ai/cli/test";

describe("CipherLoom bundle", () => {
  it("boots, persists the vault index, and invokes the executa", async () => {
    const h = await mountBundle({
      manifest: "./manifest.json",
      bundle: "./bundle",
    });

    // storage round trip (vault.index)
    await h.call("storage", "set", { key: "vault.index", value: [{ id: "1", name: "nda.txt" }] });
    const got = await h.call("storage", "get", { key: "vault.index" });
    expect(got.result.value[0].name).toBe("nda.txt");

    // executa invoke is mocked in manifest dev.mocks -> {success:true,...}
    const inv = await h.call("tools", "invoke", {
      tool_id: "tool-dev-cipherloom-CHANGEME0",
      method: "cipherloom",
      args: { action: "ask", question: "termination" },
    });
    expect(inv.ok).toBe(true);

    // window title call
    const t = await h.call("window", "set_title", { title: "CipherLoom Vault" });
    expect(t.ok).toBe(true);

    const events = h.drainEvents();
    expect(events.length).toBeGreaterThan(0);
    await h.close();
  });
});