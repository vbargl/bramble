import { popupUrl } from "../extension/helpers";
import {
	createVault,
	enterCode,
	expect,
	gotoSync,
	invite,
	PW,
	test,
	useLocalRelay,
} from "./fixtures";

// Full application pairing over real WebRTC/relay. Instrumentation only records actual outgoing
// data-channel frames and subscribes to production status events; crypto/transport are not mocked.
for (const pin of ["correct", "different", "missing"] as const) {
	test(`F4: ${pin} inviter pin is enforced before the joiner sends its static identity`, async ({
		ext,
		mobile,
	}) => {
		await createVault(ext.page);
		await ext.page.goto(popupUrl(ext.extensionId));
		await gotoSync(ext.page);
		await useLocalRelay(ext.page);
		const original = await invite(ext.page);
		const payload = JSON.parse(
			Buffer.from(original.replace("bramble-pair-1.", ""), "base64").toString("utf8"),
		);
		if (pin === "different") payload.inviterPub = Buffer.alloc(32, 23).toString("base64");
		if (pin === "missing") payload.inviterPub = "";
		const code = `bramble-pair-1.${Buffer.from(JSON.stringify(payload)).toString("base64url")}`;
		await mobile.page.evaluate(async () => {
			const audit = { sent: [] as number[], statuses: [] as string[] };
			(window as unknown as { pinAudit: typeof audit }).pinAudit = audit;
			const originalSend = RTCDataChannel.prototype.send;
			RTCDataChannel.prototype.send = function (data: unknown) {
				if (typeof data === "string") audit.sent.push(atob(data).length);
				Reflect.apply(originalSend, this, [data]);
			};
			const path = "/src/sync/sync-manager.ts";
			const manager = await import(/* @vite-ignore */ path);
			manager.onSyncStatus((message: string) => audit.statuses.push(message));
		});
		await mobile.page.getByRole("button", { name: /Create your vault/i }).click();
		await mobile.page.getByRole("button", { name: /Join a device/i }).click();
		if (pin === "missing") {
			await mobile.page.getByRole("button", { name: /Paste code instead/i }).click();
			await mobile.page.getByPlaceholder(/Paste the code from your other device/i).fill(code);
			await mobile.page.getByLabel(/Master password/i).fill(PW);
			await mobile.page.getByRole("button", { name: /Join vault/i }).click();
		} else await enterCode(mobile.page, code);
		const audit = () =>
			mobile.page.evaluate(
				() => (window as unknown as { pinAudit: { sent: number[]; statuses: string[] } }).pinAudit,
			);
		if (pin === "correct") {
			await expect(ext.page.getByText(/Is this your device\?/i)).toBeVisible({ timeout: 60_000 });
			expect((await audit()).sent.slice(0, 2)).toEqual([48, 64]);
			await ext.page.getByRole("button", { name: /They match, approve/i }).click();
			await expect(
				mobile.page.getByRole("button", { name: "Lock vault", exact: true }),
			).toBeVisible({ timeout: 60_000 });
		} else if (pin === "different") {
			await expect
				.poll(async () => (await audit()).statuses.join("\n"))
				.toMatch(/inviter key mismatch|possible MITM/);
			expect((await audit()).sent).toEqual([48]);
			await expect(ext.page.getByText(/Is this your device\?/i)).toBeHidden();
			await expect(
				mobile.page.getByRole("button", { name: "Lock vault", exact: true }),
			).toBeHidden();
		} else {
			await expect(
				mobile.page.getByText(/invalid|inviter.*pin|inviter key|pairing code/i).last(),
			).toBeVisible();
			expect((await audit()).sent).toEqual([]);
		}
	});
}
