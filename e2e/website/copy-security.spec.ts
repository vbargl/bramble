import { expect, test } from "@playwright/test";

test("F8: public network/privacy claims include observable relay metadata and optional services", async ({
	page,
}) => {
	await page.goto("/");
	await expect(page.getByText(/it can observe IP addresses and connection timing/)).toBeVisible();
	await page.getByText("Does anything get sent to your servers?", { exact: true }).click();
	await expect(
		page.getByText(
			/Optional sync, cloud backups, email aliases and breach checks make network connections/,
		),
	).toBeVisible();
	await expect(
		page.getByText(/The desktop app also checks for updates when it opens/),
	).toBeVisible();
});

test("F8: the rendered conflict FAQ promises preserved versions and requires updated clients", async ({
	page,
}) => {
	await page.goto("/");
	await page.getByText("What if I edit the same login on two devices?", { exact: true }).click();
	await expect(
		page.getByText(/Concurrent edits to the same entry are kept as separate versions/),
	).toBeVisible();
	await expect(page.getByText(/Fields do not automatically merge/)).toBeVisible();
	await expect(
		page.getByText(/Older clients can still discard conflicts, so update every device/),
	).toBeVisible();
});
