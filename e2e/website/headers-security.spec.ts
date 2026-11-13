import { createServer } from "node:http";
import { expect, test } from "@playwright/test";

test("F6: Pages serves the generated security policy without weakening endpoint-specific headers", async ({
	request,
}) => {
	const response = await request.get("/");
	expect(response.status()).toBe(200);
	const h = response.headers();
	expect(h["strict-transport-security"]).toBe("max-age=31536000");
	expect(h["x-content-type-options"]).toBe("nosniff");
	expect(h["x-frame-options"]).toBe("DENY");
	expect(h["content-security-policy"]).toContain("frame-ancestors 'none'");
	const scripts = h["content-security-policy"]
		?.split(";")
		.find((s) => s.trim().startsWith("script-src "));
	expect(scripts).toContain("'sha256-");
	expect(scripts).not.toContain("'unsafe-inline'");
	const matrix = await request.get("/.well-known/matrix/client");
	expect(matrix.status()).toBe(200);
	expect(matrix.headers()["access-control-allow-origin"]).toBe("*");
	expect(matrix.headers()["content-type"]).toContain("application/json");
	const updates = await request.get("/desktop/latest.json");
	expect(updates.status()).toBe(200);
	expect(updates.headers()["cache-control"]).toContain("max-age=300");
	expect(updates.headers()["cache-control"]).toContain("must-revalidate");
	expect(updates.headers()["content-type"]).toContain("application/json");
});

test("F6: browser executes the genuine hashed script and blocks an injected inline script", async ({
	page,
}) => {
	await page.goto("/");
	await expect(page.locator("html")).toHaveClass(/theme-ready/);
	await page.evaluate(() => {
		const audit = { injected: false, violations: [] as string[] };
		(window as unknown as { cspAudit: typeof audit }).cspAudit = audit;
		document.addEventListener("securitypolicyviolation", (e) =>
			audit.violations.push(e.effectiveDirective),
		);
		const script = document.createElement("script");
		script.textContent = "window.cspAudit.injected = true";
		document.body.appendChild(script);
	});
	await expect
		.poll(() =>
			page.evaluate(
				() => (window as unknown as { cspAudit: { violations: string[] } }).cspAudit.violations,
			),
		)
		.toContain("script-src-elem");
	expect(
		await page.evaluate(
			() => (window as unknown as { cspAudit: { injected: boolean } }).cspAudit.injected,
		),
	).toBe(false);
});

test("F6: a different origin cannot frame the website", async ({ page, baseURL }) => {
	const parent = createServer((_req, res) => {
		res.setHeader("content-type", "text/html");
		res.end(`<title>Attacker frame</title><iframe src="${baseURL}/"></iframe>`);
	});
	await new Promise<void>((resolve) => parent.listen(0, "127.0.0.1", resolve));
	try {
		const errors: string[] = [];
		page.on("console", (m) => errors.push(m.text()));
		page.on("requestfailed", (r) => errors.push(r.failure()?.errorText ?? ""));
		const address = parent.address();
		if (!address || typeof address === "string") throw new Error("no attacker port");
		await page.goto(`http://127.0.0.1:${address.port}`);
		await expect
			.poll(() => errors.join("\n"))
			.toMatch(/frame-ancestors|X-Frame-Options|ERR_BLOCKED_BY_RESPONSE/i);
		await expect(page.frameLocator("iframe").locator("html.theme-ready")).toHaveCount(0);
	} finally {
		await new Promise<void>((resolve, reject) => parent.close((e) => (e ? reject(e) : resolve())));
	}
});
