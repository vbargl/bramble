import { buildCryptoAdapter } from "@core/adapters/crypto-wasm";
import { fileRecord } from "@core/test/vault-fixtures";
import { beforeEach, describe, expect, it, vi } from "vitest";

// The KeePass export's marshalling: each attachment goes by its address in the store, never as
// bytes, and the database comes back as a path the shell copies out.

const h = vi.hoisted(() => ({
	calls: [] as { cmd: string; args: unknown }[],
	replies: {} as Record<string, unknown>,
}));

vi.mock("@tauri-apps/api/core", () => ({
	invoke: async (cmd: string, args: unknown) => {
		h.calls.push({ cmd, args });
		return h.replies[cmd];
	},
}));
vi.mock("./vault-session", () => ({
	markLocked: () => {},
	markUnlocked: () => {},
	onExternalChange: () => () => {},
	onExternalLock: () => () => {},
	onVaultStateChange: () => () => {},
}));

const { desktopCrypto } = await import("./crypto");

const VAULT = "11111111-2222-4333-8444-555555555555";

beforeEach(() => {
	h.calls = [];
	h.replies = {};
});

describe("desktop KeePass export", () => {
	it("hands the shell addresses, and gets back a file it can copy and discard", async () => {
		const record = fileRecord({ hash: "a".repeat(64) });
		h.replies.files_save_kdbx = {
			path: "/cache/open/kdbx-1/out.kdbx",
			size: 2048,
			dir: "/cache/open/kdbx-1",
		};
		h.replies.files_read_kdbx = new Uint8Array([3, 217]).buffer;

		const saved = await desktopCrypto.saveKdbx?.({
			vaultId: VAULT,
			name: "out.kdbx",
			entries: [{ strings: [] }],
			password: "pw",
			files: [{ entry: 0, record, name: "scan.pdf" }],
		});

		expect(h.calls[0]).toEqual({
			cmd: "files_save_kdbx",
			args: {
				vaultId: VAULT,
				name: "out.kdbx",
				entries: [{ strings: [] }],
				password: "pw",
				files: [
					{
						entry: 0,
						name: "scan.pdf",
						hash: record.hash,
						size: record.size,
						wrappedFek: record.wrappedFek,
						fekIv: record.fekIv,
						noncePrefix: record.noncePrefix,
					},
				],
			},
		});
		expect(saved?.size).toBe(2048);
		expect(saved?.path).toBe("/cache/open/kdbx-1/out.kdbx");
		expect(await saved?.read(0, 2)).toEqual(new Uint8Array([3, 217]));

		await saved?.release?.();
		expect(h.calls.at(-1)).toEqual({
			cmd: "files_discard_kdbx",
			args: { dir: "/cache/open/kdbx-1" },
		});
	});
});

describe("desktop portable vault (.bramble)", () => {
	const blob = {
		slotId: "S",
		salt: "SA",
		verifier: "V",
		wrapIv: "WI",
		wrappedVek: "WV",
		entriesIv: "EI",
		entriesCiphertext: "EC",
	};

	it("seals and opens through the shell, magicVersion as a number array", async () => {
		h.replies.crypto_seal_portable_vault = blob;
		h.replies.crypto_open_portable_vault = "[]";
		const magicVersion = new Uint8Array([86, 76, 84, 49, 0, 1]);

		expect(
			await desktopCrypto.sealPortableVault?.({ entriesJson: "[]", password: "pw", magicVersion }),
		).toEqual(blob);
		expect(
			await desktopCrypto.openPortableVault?.({ password: "pw", file: blob, magicVersion }),
		).toBe("[]");
		expect(h.calls).toEqual([
			{
				cmd: "crypto_seal_portable_vault",
				args: { entriesJson: "[]", password: "pw", magicVersion: [86, 76, 84, 49, 0, 1] },
			},
			{
				cmd: "crypto_open_portable_vault",
				args: { password: "pw", file: blob, magicVersion: [86, 76, 84, 49, 0, 1] },
			},
		]);
	});

	it("answers a wrong password with null", async () => {
		h.replies.crypto_open_portable_vault = null;
		expect(
			await desktopCrypto.openPortableVault?.({
				password: "nope",
				file: blob,
				magicVersion: new Uint8Array([1]),
			}),
		).toBeNull();
	});
});

// Desktop's adapter is written by hand, so a call added to the shared one can be missed here,
// and the UI offers the feature anyway (the .bramble export once failed like that).
describe("desktop crypto coverage", () => {
	it("implements every call the shared adapter does", () => {
		const shared = Object.keys(buildCryptoAdapter(async () => ({}) as never));
		expect(shared.filter((k) => !(k in desktopCrypto))).toEqual([]);
	});
});

describe("desktop mailbox crypto", () => {
	it("invokes the mailbox commands with camelCase arguments", async () => {
		h.replies.crypto_mailbox_id = "id";
		h.replies.crypto_mailbox_seal = "sealed";
		h.replies.crypto_mailbox_open = "opened";
		expect(await desktopCrypto.mailboxId?.("G")).toBe("id");
		expect(await desktopCrypto.mailboxSeal?.("G", "A", "P")).toBe("sealed");
		expect(await desktopCrypto.mailboxOpen?.("G", "A", "S")).toBe("opened");
		expect(h.calls).toEqual([
			{ cmd: "crypto_mailbox_id", args: { groupKeyB64: "G" } },
			{ cmd: "crypto_mailbox_seal", args: { groupKeyB64: "G", aad: "A", plaintext: "P" } },
			{ cmd: "crypto_mailbox_open", args: { groupKeyB64: "G", aad: "A", sealedB64: "S" } },
		]);
	});
});

it("native creation and rotation return no vault key to the webview", async () => {
	h.replies.crypto_generate_vek = "STALE_SHELL_KEY";
	h.replies.crypto_rotate_vek = "STALE_SHELL_KEY";
	expect(await desktopCrypto.generateVek()).toBeUndefined();
	expect(await desktopCrypto.rotateVek()).toBeUndefined();
	expect(h.calls.map((c) => c.cmd)).toEqual(["crypto_generate_vek", "crypto_rotate_vek"]);
});
