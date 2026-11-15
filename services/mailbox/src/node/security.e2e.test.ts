import { randomBytes } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { MembersResponseSchema } from "@vault/core/src/sync/mailbox/protocol.ts";
import { describe, expect, it } from "vitest";
import { makeRemoteDevice } from "../test/harness.ts";
import { startServer } from "./server.ts";

// The actual Node HTTP adapter, SQLite schema and disk store, not app.request().
// Encoded terminators previously skipped /v1/* middleware in Hono's wildcard router.
for (const token of [undefined, "security-e2e-private-token"]) {
	describe(`F7 real mailbox HTTP boundary (${token ? "private" : "public"})`, () => {
		it("keeps authentication on encoded paths and permits a genuinely signed control", async () => {
			const dir = await mkdtemp(join(tmpdir(), "bramble-security-mailbox-"));
			const server = await startServer({ PORT: "0", DATA_DIR: dir, MAILBOX_TOKEN: token });
			try {
				const signer = await makeRemoteDevice(server.url);
				const id = randomBytes(32).toString("base64url");
				const created = await signer.request(
					"POST",
					`/v1/mailboxes/${id}`,
					{ members: [signer.sigKey] },
					{ token },
				);
				expect(created.status).toBe(200);
				const control = await signer.request("GET", `/v1/mailboxes/${id}/members`, undefined, {
					token,
				});
				expect(control.status).toBe(200);
				expect(MembersResponseSchema.parse(await control.json()).members).toHaveLength(1);
				for (const path of [
					`/v1/mailboxes/${id}/members`,
					...["%0A", "%0D", "%E2%80%A8", "%E2%80%A9"].flatMap((terminator) => [
						`/v1/${terminator}`,
						`/v1/mailboxes/${id}${terminator}/members`,
					]),
				]) {
					const res = await fetch(server.url + path);
					expect(res.status, path).toBe(token ? 403 : 401);
					expect(await res.json()).toEqual({ error: token ? "token_required" : "bad_signature" });
					if (token) {
						const tokenOnly = await fetch(server.url + path, {
							headers: { "x-bramble-token": token },
						});
						expect(tokenOnly.status, path).toBe(401);
						expect(await tokenOnly.json()).toEqual({ error: "bad_signature" });
					}
				}
			} finally {
				await server.close();
				await rm(dir, { recursive: true, force: true });
			}
		});
	});
}
