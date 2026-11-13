import type { Page, Worker } from "@playwright/test";
import {
	canonicalRosterEntry,
	type RosterEntry,
	type RosterPayload,
} from "../../packages/core/src/sync/roster";
import { backgroundWorker } from "../extension/helpers";
import { addLogin, expect, gotoSync, PW, pairWithPhone, test } from "./fixtures";

async function group(worker: Worker) {
	return worker.evaluate(async () => {
		const all = await chrome.storage.local.get(null);
		const key = Object.keys(all).find((k) => k.startsWith("sync.group:"));
		if (!key) return null;
		return { key, value: all[key] as { groupKey: string; roster: RosterPayload } };
	});
}
async function phoneGroup(page: Page): Promise<{ roster: RosterPayload }> {
	return page.evaluate(() => {
		const key = Object.keys(localStorage).find((k) => k.includes("meta:sync.group:"));
		if (!key) throw new Error("phone has no sync group");
		return JSON.parse(localStorage.getItem(key)!);
	});
}

for (const attack of [
	"unsigned-member",
	"member-signed-without-admission",
	"authority-replacement",
] as const) {
	test(`F2: an authenticated compromised member cannot gossip ${attack}`, async ({
		ext,
		mobile,
	}) => {
		const popup = await pairWithPhone(ext, mobile);
		await addLogin(popup, "trusted-positive-control");
		await expect(mobile.page.getByText("trusted-positive-control", { exact: true })).toBeVisible({
			timeout: 30_000,
		});
		const worker = await backgroundWorker(ext.context);
		const stored = (await group(worker))!;
		expect(stored.value.roster.devices).toHaveLength(2);
		expect(stored.value.roster.devices.every((d) => d.sig && d.sigKey)).toBe(true);
		const trusted = await phoneGroup(mobile.page);
		const initialAuthority = trusted.roster.devices.map((d) => [d.id, d.admissionKey]);
		let forged: RosterEntry = {
			id: "rogue-audit-device",
			publicKey: Buffer.alloc(32, 17).toString("base64"),
			label: "ROGUE",
			addedAt: Date.now(),
			hlc: { wall: Date.now(), counter: 0, node: "rogue-audit-device" },
		};
		if (attack === "member-signed-without-admission") {
			// A compromised member has a signing key, but not the re-entered master password.
			const signing = await popup.evaluate(() =>
				chrome.runtime.sendMessage({ type: "SYNC_SIGNING_PUBKEY" }),
			);
			expect(signing.ok).toBe(true);
			forged.sigKey = signing.data;
		} else if (attack === "authority-replacement") {
			const keypair = await worker.evaluate(async () => {
				const all = await chrome.storage.local.get(null);
				const key = Object.keys(all).find((k) => k.startsWith("sync.deviceKeypair:"));
				return all[key!].publicKey as string;
			});
			forged = {
				...stored.value.roster.devices.find((d) => d.publicKey === keypair)!,
				admissionKey: Buffer.alloc(32, 29).toString("base64"),
				hlc: { wall: Date.now(), counter: 1, node: "rogue-audit-device" },
			};
		}
		if (attack !== "unsigned-member") {
			const signed = await popup.evaluate(
				(canonical) =>
					chrome.runtime.sendMessage({ type: "SYNC_SIGN_ENTRY", payload: { canonical } }),
				canonicalRosterEntry(forged),
			);
			expect(signed.ok).toBe(true);
			forged.sig = signed.data;
			// Establish that admission/pinning rejects a genuinely valid signature, not malformed crypto.
			const valid = await popup.evaluate(
				async ({ url, key, canonical, signature }) => {
					const wasm = await import(/* @vite-ignore */ url);
					await wasm.default();
					return wasm.roster_verify(key, canonical, signature);
				},
				{
					url: `chrome-extension://${ext.extensionId}/wasm/vault_crypto.js`,
					key: forged.sigKey!,
					canonical: canonicalRosterEntry(forged),
					signature: forged.sig!,
				},
			);
			expect(valid).toBe(true);
		}
		const poisoned = {
			...stored.value,
			roster: {
				...stored.value.roster,
				devices: [...stored.value.roster.devices.filter((d) => d.id !== forged.id), forged],
			},
		};
		// Only mutate the attacker's local store. The victim receives it through real encrypted
		// roster gossip; never call its merge/verify functions from the test.
		await worker.evaluate(({ key, value }) => chrome.storage.local.set({ [key]: value }), {
			key: stored.key,
			value: poisoned,
		});
		await addLogin(popup, `delivery-control-${attack}`);
		await expect(mobile.page.getByText(`delivery-control-${attack}`, { exact: true })).toBeVisible({
			timeout: 30_000,
		});
		const received = await phoneGroup(mobile.page);
		expect(received.roster.devices.some((d) => d.id === "rogue-audit-device")).toBe(false);
		expect(received.roster.devices.map((d) => [d.id, d.admissionKey])).toEqual(initialAuthority);
		if (attack === "unsigned-member") {
			await gotoSync(mobile.page);
			await mobile.page.getByRole("button", { name: /^Remove / }).click();
			await mobile.page.getByRole("button", { name: "Remove", exact: true }).click();
			await expect.poll(async () => (await phoneGroup(mobile.page)).roster.revoked.length).toBe(1);
			await addLogin(popup, "revoked-member-must-not-deliver");
			// Two full four-second rebroadcast periods, after a successful delivery control above.
			await mobile.page.waitForTimeout(9_000);
			await mobile.page.reload();
			await expect(
				mobile.page.getByText("revoked-member-must-not-deliver", { exact: true }),
			).toBeHidden();
			expect(
				(await phoneGroup(mobile.page)).roster.devices.some((d) => d.id === "rogue-audit-device"),
			).toBe(false);
		}
	});
}

test("F2: changing the password disconnects persistently; a fresh group has fresh authority", async ({
	ext,
	mobile,
}) => {
	const popup = await pairWithPhone(ext, mobile);
	const worker = await backgroundWorker(ext.context);
	const before = (await group(worker))!;
	const newPassword = "New-9Kr7-Lm2x-Wq8n";
	await popup.getByRole("button", { name: "Settings", exact: true }).click();
	await popup.getByRole("button", { name: "Security", exact: true }).click();
	await popup.getByRole("button", { name: "Change", exact: true }).click();
	await popup.getByLabel("Current password", { exact: true }).fill(PW);
	await popup.getByLabel("New password", { exact: true }).fill(newPassword);
	await popup.getByLabel("Confirm new password", { exact: true }).fill(newPassword);
	await popup.getByRole("button", { name: "Update password", exact: true }).click();
	await expect(popup.getByText("Master password updated.")).toBeVisible();
	expect(await group(worker)).toBeNull();
	await popup.reload();
	expect(await group(worker)).toBeNull();
	await popup.getByRole("button", { name: "Sync", exact: true }).click();
	await popup.getByRole("button", { name: "Add a device", exact: true }).last().click();
	await popup.locator('input[type="password"]').first().fill(newPassword);
	await popup.getByRole("button", { name: "Continue", exact: true }).click();
	await expect(popup.locator("input[readonly]")).toBeVisible();
	const fresh = (await group(worker))!;
	expect(fresh.value.groupKey).not.toBe(before.value.groupKey);
	expect(fresh.value.roster.devices).toHaveLength(1);
	expect(before.value.roster.devices.map((d) => d.admissionKey)).not.toContain(
		fresh.value.roster.devices[0]!.admissionKey,
	);
});
