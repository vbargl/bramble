import { describe, expect, it, vi } from "vitest";
import { loadBackground, pageSender } from "../test/test-harness";

// What the desktop app pushes is the authenticator KEY, because it holds the same index this
// browser does and has no TOTP implementation of its own. Filling that verbatim would type the
// seed into the page's one-time-code field: the wrong value, and the one secret a page must
// never see. The code is computed on this side, exactly as it is for a local fill.

const h = vi.hoisted(() => ({
	/** The handler the autofill side registers for a fill the app pushes. */
	onFill: null as null | ((fill: Record<string, unknown>) => void),
}));

// Only this seam is under test. Reaching the handler through a real native port would re-test
// the link's routing, which desktop-link.test.ts already covers.
vi.mock("./desktop-link", () => ({
	onDesktopFillRequest: (handler: (fill: Record<string, unknown>) => void) => {
		h.onFill = handler;
	},
	linkIsHeld: () => true,
	reportActiveTab: async () => {},
	openDesktopLink: async () => false,
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

/** RFC 6238's SHA1 secret, whose 6-digit code at T=59s is a published vector. */
const SEED = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
const TARGET = "a".repeat(64);
const CODE_AT_59S = "287082";

/** Push one fill from the app and return the payload the page was sent. */
async function fillFromApp(totpKey: string | null): Promise<Record<string, unknown> | undefined> {
	const bg = await loadBackground({
		openTabs: [{ id: 11, url: "https://example.com/login" }],
		tabReply: (_id, m) =>
			m.type === "DESKTOP_FILL_TARGET"
				? { target: TARGET, origin: "https://example.com" }
				: undefined,
	});
	await bg.flush();
	expect(h.onFill).toBeTypeOf("function");
	// Pinned so the assertion is a fixed vector rather than whatever the clock says.
	const clock = vi.spyOn(Date, "now").mockReturnValue(59_000);
	h.onFill?.({ username: "octocat", password: "hunter2", totpKey, target: TARGET });
	await bg.flush();
	const claimed = await bg.send(
		{ type: "DESKTOP_FILL_CLAIM", target: TARGET },
		pageSender("example.com", 11),
	);
	clock.mockRestore();
	expect(bg.state.tabMessages.some((m) => JSON.stringify(m.message).includes("hunter2"))).toBe(
		false,
	);
	return claimed.resp.data as Record<string, unknown>;
}

describe("a fill pushed by the desktop app", () => {
	it("fills the live code for an otpauth key, and never the key", async () => {
		const payload = await fillFromApp(
			`otpauth://totp/Example:octocat?secret=${SEED}&issuer=Example`,
		);
		expect(payload).toEqual({ username: "octocat", password: "hunter2", totp: CODE_AT_59S });
		expect(JSON.stringify(payload)).not.toContain(SEED);
	});

	it("fills the live code for a bare base32 seed", async () => {
		// The index carries whichever form the entry was saved with; both are keys, not codes.
		const payload = await fillFromApp(SEED);
		expect(payload?.totp).toBe(CODE_AT_59S);
	});

	it("drops a key it cannot parse rather than filling it", async () => {
		const payload = await fillFromApp("not a key!!");
		expect(payload?.totp).toBeUndefined();
		expect(JSON.stringify(payload)).not.toContain("not a key");
	});

	it("fills a login with no authenticator key at all", async () => {
		const payload = await fillFromApp(null);
		expect(payload).toEqual({ username: "octocat", password: "hunter2" });
	});
});

for (const [name, target, host, tabId, frameId] of [
	["same-origin replacement", "b".repeat(64), "example.com", 11, 0],
	["cross-origin replacement", TARGET, "evil.example", 11, 0],
	["sibling subdomain", TARGET, "sub.example.com", 11, 0],
	["different port", TARGET, "example.com:8443", 11, 0],
	["another tab", TARGET, "example.com", 12, 0],
	["child frame", TARGET, "example.com", 11, 1],
	["legacy unbound fill", undefined, "example.com", 11, 0],
] as const)
	it(`refuses ${name}`, async () => {
		const bg = await loadBackground({
			openTabs: [{ id: 11, url: "https://example.com/login" }],
			tabReply: (_id, m) =>
				m.type === "DESKTOP_FILL_TARGET"
					? { target: TARGET, origin: "https://example.com" }
					: undefined,
		});
		await bg.flush();
		h.onFill?.({ username: "u", password: "NEVER_PUSH", target });
		await bg.flush();
		const claimed = await bg.send(
			{ type: "DESKTOP_FILL_CLAIM", target },
			pageSender(host, tabId, frameId),
		);
		expect(claimed.resp.ok).toBe(false);
		expect(JSON.stringify(bg.state.tabMessages)).not.toContain("NEVER_PUSH");
	});
it("consumes the grant exactly once", async () => {
	const bg = await loadBackground({
		openTabs: [{ id: 11, url: "https://example.com/login" }],
		tabReply: () => ({ target: TARGET, origin: "https://example.com" }),
	});
	await bg.flush();
	h.onFill?.({ username: "u", password: "s", target: TARGET });
	await bg.flush();
	expect(
		(await bg.send({ type: "DESKTOP_FILL_CLAIM", target: TARGET }, pageSender("example.com", 11)))
			.resp.ok,
	).toBe(true);
	expect(
		(await bg.send({ type: "DESKTOP_FILL_CLAIM", target: TARGET }, pageSender("example.com", 11)))
			.resp.ok,
	).toBe(false);
});

it("refuses the original document after the active tab changes", async () => {
	const tabs = [{ id: 11, url: "https://example.com/login" }];
	const bg = await loadBackground({
		openTabs: tabs,
		tabReply: () => ({ target: TARGET, origin: "https://example.com" }),
	});
	await bg.flush();
	h.onFill?.({ username: "u", password: "NEVER_PUSH", target: TARGET });
	await bg.flush();
	tabs[0] = { id: 12, url: "https://evil.example/" };
	expect(
		(await bg.send({ type: "DESKTOP_FILL_CLAIM", target: TARGET }, pageSender("example.com", 11)))
			.resp.ok,
	).toBe(false);
	expect(JSON.stringify(bg.state.tabMessages)).not.toContain("NEVER_PUSH");
});
