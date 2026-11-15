import { desk, expect, test } from "./fixtures";

test.skip(
	process.platform !== "darwin",
	"Requires the real native app in the isolated macOS fixture; this is not a web-adapter mock.",
);
test.describe.configure({ mode: "serial" });

test("F5: real webview/native create and rotate return no key while encryption still works", async ({
	desktop,
}) => {
	expect(desktop.home).toBeTruthy();
	const result = await desk<{
		created: unknown;
		rotated: unknown;
		before: string;
		after: string;
		oldRejected: boolean;
	}>(`
		const invoke = window.__TAURI_INTERNALS__.invoke;
		const created = await invoke("crypto_generate_vek");
		const old = await invoke("crypto_encrypt_with_vek", { plaintext: "synthetic-before" });
		const before = await invoke("crypto_decrypt_with_vek", { iv: old.iv, ciphertext: old.ciphertext });
		const rotated = await invoke("crypto_rotate_vek");
		let oldRejected = false;
		try { await invoke("crypto_decrypt_with_vek", { iv: old.iv, ciphertext: old.ciphertext }); } catch { oldRejected = true; }
		const fresh = await invoke("crypto_encrypt_with_vek", { plaintext: "synthetic-after" });
		const after = await invoke("crypto_decrypt_with_vek", { iv: fresh.iv, ciphertext: fresh.ciphertext });
		return { created, rotated, before, after, oldRejected };
	`);
	expect(result.created).toBeNull();
	expect(result.rotated).toBeNull();
	expect(result.before).toBe("synthetic-before");
	expect(result.after).toBe("synthetic-after");
	expect(result.oldRejected).toBe(true);
});

test("F5 OPEN: a reusable native VEK cannot be exported into the renderer", async ({ desktop }) => {
	expect(desktop.home).toBeTruthy();
	const result = await desk<{ available: boolean; bytes: number }>(`
		const invoke = window.__TAURI_INTERNALS__.invoke;
		await invoke("crypto_generate_vek");
		try { const key = await invoke("crypto_export_vek"); return { available: typeof key === "string", bytes: typeof key === "string" ? atob(key).length : 0 }; }
		catch { return { available: false, bytes: 0 }; }
	`);
	// Never send the synthetic key back to Playwright logs. Mark only this explicit known
	// crossing as expected failure; setup/IPC errors must fail normally.
	if (result.available && result.bytes === 32)
		test.fail(
			true,
			"Explicit export/enrollment/biometric crossings remain open; lifecycle no-return is only a partial F5 fix.",
		);
	expect(result.available).toBe(false);
});
