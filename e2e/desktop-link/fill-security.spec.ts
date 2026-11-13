import type { Worker } from "@playwright/test";
import { desk, expect, test } from "./fixtures";
import { desktopAddLogin, desktopApprove, desktopConnect, linkFromSetup } from "./steps";

test.skip(
	process.platform !== "darwin",
	"Real desktop/native-link E2E needs the isolated macOS keychain fixture; a skipped case is not security acceptance.",
);
test.describe.configure({ mode: "serial" });
const SECRET = "Synthetic-desktop-fill-9Kr7";
const USER = "security-e2e@example.invalid";
const LOGIN = "Audit desktop fill";
const HTML = `<title>Security login</title><form><input autocomplete="username" name="username"><input autocomplete="current-password" name="password" type="password"></form>`;

test.beforeAll(async ({ desktop }) => {
	expect(desktop.home).toBeTruthy();
	await desktopAddLogin(LOGIN, { username: USER, password: SECRET });
});

async function arm(worker: Worker) {
	await worker.evaluate(() => {
		const original = chrome.tabs.sendMessage.bind(chrome.tabs);
		const gate = { armed: true, held: [] as (() => Promise<unknown>)[] };
		(globalThis as unknown as { fillGate: typeof gate }).fillGate = gate;
		chrome.tabs.sendMessage = ((...args: Parameters<typeof chrome.tabs.sendMessage>) => {
			const message = args[1] as { type?: string };
			// Delay only the final delivery. On old builds this is the secret push; on fixed
			// builds it is a non-secret wakeup. Native Noise and all authorization remain real.
			if (gate.armed && ["DESKTOP_FILL", "DESKTOP_FILL_READY"].includes(message.type ?? "")) {
				return new Promise<unknown>((resolve, reject) =>
					gate.held.push(() =>
						Promise.resolve(Reflect.apply(original, chrome.tabs, args)).then(resolve, reject),
					),
				);
			}
			return Reflect.apply(original, chrome.tabs, args);
		}) as typeof chrome.tabs.sendMessage;
	});
}
async function release(worker: Worker) {
	await worker.evaluate(async () => {
		const gate = (
			globalThis as unknown as { fillGate: { armed: boolean; held: (() => Promise<unknown>)[] } }
		).fillGate;
		gate.armed = false;
		for (const send of gate.held) await send();
	});
}

for (const scenario of [
	"unchanged",
	"same-origin-navigation",
	"cross-origin-navigation",
	"scheme-change",
	"port-change",
	"active-tab-switch",
	"expired-grant",
	"replayed-grant",
	"bfcache-restore",
] as const) {
	test(`F1: real native fill ${scenario}`, async ({ ext }) => {
		await desktopConnect();
		await linkFromSetup(ext.page);
		await ext.page.getByRole("button", { name: "They match", exact: true }).click();
		await desktopApprove();
		await ext.context.route(/https?:\/\/(account|attacker)\.invalid(?::\d+)?\//, (route) =>
			route.fulfill({ contentType: "text/html", body: HTML }),
		);
		await ext.context.addInitScript(() =>
			window.addEventListener("pageshow", (event) => {
				document.documentElement.dataset.auditBfcache = String(event.persisted);
			}),
		);
		const original = await ext.context.newPage();
		await original.goto("https://account.invalid/login");
		await original.bringToFront();
		await expect
			.poll(() => desk('return await window.__TAURI_INTERNALS__.invoke("spotlight_active_tab");'))
			.toBe("account.invalid");
		const worker = ext.context.serviceWorkers()[0]!;
		await arm(worker);
		await desk(`const hits = await window.__TAURI_INTERNALS__.invoke("spotlight_search", { query: ${JSON.stringify(LOGIN)}, limit: 20 });
			const hit = hits.find(h => h.name === ${JSON.stringify(LOGIN)}); if (!hit) throw new Error("synthetic entry missing");
			await window.__TAURI_INTERNALS__.invoke("spotlight_request_fill", { id: hit.id });`);
		await expect
			.poll(() =>
				worker.evaluate(
					() => (globalThis as unknown as { fillGate: { held: unknown[] } }).fillGate.held.length,
				),
			)
			.toBe(1);
		let destination = original;
		if (scenario === "same-origin-navigation")
			await destination.goto("https://account.invalid/replacement");
		if (scenario === "cross-origin-navigation")
			await destination.goto("https://attacker.invalid/login");
		if (scenario === "scheme-change") await destination.goto("http://account.invalid/login");
		if (scenario === "port-change") await destination.goto("https://account.invalid:8443/login");
		if (scenario === "active-tab-switch") {
			destination = await ext.context.newPage();
			await destination.goto("https://attacker.invalid/login");
			await destination.bringToFront();
		}
		if (scenario === "bfcache-restore") {
			await original.goto("https://attacker.invalid/away");
			await original.goBack();
			await expect(
				original.locator("html"),
				"BFCache must actually be staged; a reload does not exercise this case",
			).toHaveAttribute("data-audit-bfcache", "true");
		}
		if (scenario === "expired-grant") await destination.waitForTimeout(10_500);
		await release(worker);
		if (scenario === "replayed-grant") {
			await expect(original.locator('input[name="password"]')).toHaveValue(SECRET);
			await original.locator('input[name="username"]').fill("");
			await original.locator('input[name="password"]').fill("");
			await release(worker);
		}
		if (scenario === "unchanged") {
			await expect(destination.locator('input[name="password"]')).toHaveValue(SECRET);
			await expect(destination.locator('input[name="username"]')).toHaveValue(USER);
		} else {
			// The delivery has been released, not merely delayed beyond the assertion. Observe
			// input values throughout a bounded settle window after actual release.
			const observed = await destination.evaluate(async () => {
				const values: string[] = [];
				const record = () =>
					values.push(...[...document.querySelectorAll("input")].map((el) => el.value));
				const timer = setInterval(record, 10);
				record();
				await new Promise((resolve) => setTimeout(resolve, 1_500));
				clearInterval(timer);
				return values;
			});
			expect(observed).not.toContain(SECRET);
			expect(observed).not.toContain(USER);
			await expect(destination.locator('input[name="password"]')).toHaveValue("");
		}
	});
}
