import { popupUrl } from "../extension/helpers";
import { createVault, expect, gotoSync, invite, test, useLocalRelay } from "./fixtures";

test("F8: the real invite UI calls the pairing code private and requires matching symbols", async ({
	ext,
}) => {
	await createVault(ext.page);
	await ext.page.goto(popupUrl(ext.extensionId));
	await gotoSync(ext.page);
	await expect(
		ext.page.getByText(
			/Generate a one-time pairing code for your other device. Keep it private while it is on screen/,
		),
	).toBeVisible();
	await expect(ext.page.getByText(/No vault secrets in the code/)).toBeHidden();
	await useLocalRelay(ext.page);
	const code = await invite(ext.page);
	expect(code).toMatch(/^bramble-pair-1\./);
	await expect(ext.page.getByText(/Keep it private: anyone/)).toBeVisible();
	await expect(
		ext.page.getByText(/matching symbols on both devices before anything is sent/),
	).toBeVisible();
});
