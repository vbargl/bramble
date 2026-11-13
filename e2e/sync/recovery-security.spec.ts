import type { Page, Worker } from "@playwright/test";
import { decodeVaultBlob } from "../../packages/core/src/vault-format";
import { backgroundWorker, popupUrl } from "../extension/helpers";
import { addLogin, expect, gotoSync, PW, pairWithPhone, test } from "./fixtures";

// Real UI, two browser profiles, production relay/Noise/WASM and persistent vault bytes.
// This is not a claim of attachment recovery or native mobile/desktop acceptance.
async function snapshot(worker: Worker) {
	return worker.evaluate(async () => {
		const all = await chrome.storage.local.get(null);
		const key = Object.keys(all).find((k) => k.startsWith("vault-blob-b64:"));
		if (!key) throw new Error("no persisted vault");
		return {
			blob: all[key] as string,
			groups: Object.keys(all).filter((k) => k.startsWith("sync.group:")),
		};
	});
}
async function exportKey(page: Page): Promise<string> {
	const result = await page.evaluate(() =>
		chrome.runtime.sendMessage({ type: "CRYPTO_EXPORT_VEK" }),
	);
	expect(result.ok).toBe(true);
	expect(result.data).toEqual(expect.any(String));
	return result.data;
}
async function canOpen(page: Page, extensionId: string, key: string, blobB64: string) {
	const blob = decodeVaultBlob(new Uint8Array(Buffer.from(blobB64, "base64")));
	return page.evaluate(
		async ({ url, key, iv, ciphertext }) => {
			const wasm = await import(/* @vite-ignore */ url);
			await wasm.default();
			wasm.unlock_with_vek(key);
			try {
				wasm.decrypt_with_vek(iv, ciphertext);
				return true;
			} catch {
				return false;
			} finally {
				wasm.lock();
			}
		},
		{
			url: `chrome-extension://${extensionId}/wasm/vault_crypto.js`,
			key,
			iv: Buffer.from(blob.entriesIv).toString("base64"),
			ciphertext: Buffer.from(blob.entriesCiphertext).toString("base64"),
		},
	);
}
async function rotate(page: Page) {
	await page.getByRole("button", { name: "Settings", exact: true }).click();
	await page.getByRole("button", { name: "Security", exact: true }).click();
	await page.getByRole("button", { name: "Rotate this vault's secret", exact: true }).click();
	await page.getByLabel("Master password", { exact: true }).fill(PW);
	await page.getByRole("button", { name: "Rotate secret", exact: true }).click();
}

test("F3: old stolen VEK cannot open the rotated vault; the old group stays disconnected after reload", async ({
	ext,
	mobile,
}) => {
	const popup = await pairWithPhone(ext, mobile);
	await addLogin(popup, "before-key-rotation");
	await expect(mobile.page.getByText("before-key-rotation", { exact: true })).toBeVisible({
		timeout: 30_000,
	});
	const worker = await backgroundWorker(ext.context);
	const before = await snapshot(worker);
	expect(before.groups).toHaveLength(1);
	const oldKey = await exportKey(popup);
	// Independent WASM instance: attacker validation must not replace the live vault key.
	const observer = await ext.context.newPage();
	await observer.goto(popupUrl(ext.extensionId));
	expect(await canOpen(observer, ext.extensionId, oldKey, before.blob)).toBe(true);
	await worker.evaluate(() =>
		chrome.storage.local.set({ "dev.flagOverrides": { rotateVaultSecret: true } }),
	);
	await popup.reload();
	await rotate(popup);
	await expect(popup.getByText(/Done. Your old recovery code no longer works/)).toBeVisible();
	const after = await snapshot(worker);
	expect(after.groups).toHaveLength(0);
	expect(after.blob).not.toBe(before.blob);
	expect(await canOpen(observer, ext.extensionId, oldKey, after.blob)).toBe(false);
	expect(await canOpen(observer, ext.extensionId, await exportKey(popup), after.blob)).toBe(true);
	await popup.reload();
	expect((await snapshot(worker)).groups).toHaveLength(0);
	await gotoSync(popup);
	await expect(popup.getByText(/THIS DEVICE/i)).toBeHidden();
});

test("F3 OPEN: complete recovery also supports vaults with attachments", async ({
	ext,
	mobile,
}) => {
	const popup = await pairWithPhone(ext, mobile);
	await addLogin(popup, "attachment-recovery");
	await popup.getByText("attachment-recovery", { exact: true }).click();
	await popup.locator('input[type="file"]').setInputFiles({
		name: "secret.txt",
		mimeType: "text/plain",
		buffer: Buffer.from("synthetic attachment"),
	});
	await expect(popup.getByText("secret.txt", { exact: true })).toBeVisible();
	const worker = await backgroundWorker(ext.context);
	await worker.evaluate(() =>
		chrome.storage.local.set({ "dev.flagOverrides": { rotateVaultSecret: true } }),
	);
	await popup.goto(popupUrl(ext.extensionId));
	await rotate(popup);
	await expect(
		popup.getByText("Rotating the key isn't available yet for a vault with attachments."),
	).toBeVisible();
	test.fail(
		true,
		"Attachment key rewrapping is not implemented: the application explicitly refused recovery.",
	);
	await expect(popup.getByText(/Done. Your old recovery code no longer works/)).toBeVisible({
		timeout: 5_000,
	});
});
