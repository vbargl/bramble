import type { webcrypto } from "node:crypto";
import { canonicalRequest, HEADERS, sha256Hex } from "@vault/core/src/sync/mailbox/protocol.ts";
import { describe, expect, it } from "vitest";
import { type AppDeps, createApp } from "./app.ts";

// No database needed: unauthenticated requests must fail BEFORE routing or persistence.
function app() {
	return createApp({
		db: {} as AppDeps["db"],
		bodies: {} as AppDeps["bodies"],
		entitlement: { canPost: async () => true },
		now: () => 1800000000000,
		config: { token: null, quotaBytes: null, retentionMaxDays: 365 },
	});
}
describe("mailbox wildcard authentication (GHSA-h7mg-cq63-vhpq)", () => {
	for (const suffix of ["%0A", "%0D", "%E2%80%A8", "%E2%80%A9", "unknown", "mailboxes/unknown"]) {
		it(`authenticates /v1/${suffix} before even the not-found handler`, async () => {
			const response = await app().request(`/v1/${suffix}`);
			expect(response.status).toBe(401);
			expect(await response.json()).toEqual({ error: "bad_signature" });
		});
	}
	it("keeps the public health probe available", async () => {
		expect((await app().request("/health")).status).toBe(200);
	});
	it("allows a correctly signed request through the same gate", async () => {
		const a = app();
		a.get("/v1/probe", (c) => c.json({ signer: c.var.sigKey }));
		const pair = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, [
			"sign",
			"verify",
		])) as unknown as webcrypto.CryptoKeyPair;
		const key = Buffer.from(await crypto.subtle.exportKey("raw", pair.publicKey)).toString(
			"base64",
		);
		const time = 1800000000000;
		const hash = await sha256Hex(new Uint8Array());
		const message = canonicalRequest({
			method: "GET",
			pathAndQuery: "/v1/probe",
			time,
			contentSha256: hash,
		});
		const sig = Buffer.from(
			await crypto.subtle.sign("Ed25519", pair.privateKey, new TextEncoder().encode(message)),
		).toString("base64");
		const response = await a.request("/v1/probe", {
			headers: {
				[HEADERS.key]: key,
				[HEADERS.time]: String(time),
				[HEADERS.contentSha256]: hash,
				[HEADERS.sig]: sig,
			},
		});
		expect(response.status).toBe(200);
		expect(await response.json()).toEqual({ signer: key });
	});
});
