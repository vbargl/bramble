import { expect, it, vi } from "vitest";
import { loadBackground } from "../test/test-harness";

const TARGET = "a".repeat(64);

const h = vi.hoisted(() => ({
	up: false,
	report: vi.fn(),
	connected: null as null | (() => void),
}));
vi.mock("./desktop-link", () => ({
	onDesktopFillRequest: () => {},
	onDesktopLinkConnected: (fn: () => void) => {
		h.connected = fn;
	},
	linkIsHeld: () => h.up,
	reportActiveTab: h.report,
	openDesktopLink: async () => {
		await new Promise((r) => setTimeout(r, 10));
		h.up = true;
		h.connected?.();
		return true;
	},
	openSyncLink: async () => false,
	closeSyncLink: async () => {},
	openBlobLink: () => {},
	closeBlobLink: () => {},
	sendSyncFrame: async () => false,
	sendBlobFrame: async () => false,
	blobLinkUp: () => false,
	desktopSyncKey: async () => null,
	setEnrollFrameSink: () => {},
}));
async function start() {
	h.up = false;
	h.connected = null;
	h.report.mockClear();
	const bg = await loadBackground({
		openTabs: [{ id: 11, url: "https://example.com/login" }],
		tabReply: (_id, message) =>
			message.type === "DESKTOP_FILL_TARGET"
				? { target: TARGET, origin: "https://example.com" }
				: undefined,
	});
	await new Promise((r) => setTimeout(r, 40));
	expect(h.up).toBe(true);
	return bg;
}
it("reports the restored active page after the desktop connection becomes ready", async () => {
	await start();
	expect(h.report).toHaveBeenCalledWith("example.com", TARGET);
});
it("control: a later URL change reports the page through the same connection", async () => {
	const bg = await start();
	for (const listener of bg.state.tabListeners.updated)
		listener(11, { url: "https://example.com/login" });
	await bg.flush();
	expect(h.report).toHaveBeenCalledWith("example.com", TARGET);
});

it("reports the active page when the desktop reconnects without a tab change", async () => {
	await start();
	h.report.mockClear();
	h.connected?.();
	await new Promise((r) => setTimeout(r, 0));
	expect(h.report).toHaveBeenCalledWith("example.com", TARGET);
});
it("refreshes the page when another browser window gains focus", async () => {
	const bg = await start();
	h.report.mockClear();
	for (const fn of bg.state.windowFocusListeners) fn(7);
	await bg.flush();
	expect(h.report).toHaveBeenCalledWith("example.com", TARGET);
});

it("keeps the last target when focus leaves the browser for Quick Access", async () => {
	const bg = await start();
	h.report.mockClear();
	for (const fn of bg.state.windowFocusListeners) fn(-1);
	await bg.flush();
	expect(h.report).not.toHaveBeenCalled();
});
