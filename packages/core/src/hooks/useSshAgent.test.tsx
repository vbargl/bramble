/** @vitest-environment happy-dom */
import { act, cleanup, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { SshAgentRefusal } from "../adapters/ssh-agent";
import { type Platform, PlatformProvider } from "../context/PlatformContext";
import {
	agentKeys,
	PREF_SSH_AGENT_KEYS,
	resetSshAgentCache,
	useSshAgentKey,
	useSshAgentSync,
} from "./useSshAgent";
import type { Entry } from "./useVault";

const h = vi.hoisted(() => ({ entries: [] as unknown[], isLocked: false }));
vi.mock("./useVault", () => ({
	useVault: () => ({ entries: h.entries, isLocked: h.isLocked }),
}));

afterEach(() => {
	cleanup();
	resetSshAgentCache();
	h.entries = [];
	h.isLocked = false;
});

function sshKey(id: string, extra: Partial<Entry> = {}): Entry {
	return {
		id,
		type: "ssh-key",
		name: `key ${id}`,
		publicKey: "",
		privateKey: `private ${id}`,
		...extra,
	} as Entry;
}

function makePlatform(
	stored: string[] | undefined,
	refusals: Record<string, SshAgentRefusal> = {},
) {
	const setKeys = vi.fn(async () => refusals);
	const setMeta = vi.fn(async () => {});
	const platform = {
		storage: { getMeta: vi.fn(async () => stored), setMeta },
		sshAgent: { isAvailable: vi.fn(async () => true), setKeys },
	} as unknown as Platform;
	return { platform, setKeys, setMeta };
}

/** Runs the sync and shows one entry's checkbox state, with a button per direction. */
function Probe({ id = "a" }: { id?: string }) {
	useSshAgentSync();
	const { available, ticked, refusal, setTicked } = useSshAgentKey(id);
	return (
		<div>
			<span data-testid="available">{String(available)}</span>
			<span data-testid="ticked">{String(ticked)}</span>
			<span data-testid="refusal">{refusal ?? ""}</span>
			<button type="button" onClick={() => void setTicked(true)}>
				tick
			</button>
			<button type="button" onClick={() => void setTicked(false)}>
				untick
			</button>
		</div>
	);
}

function mount(platform: Platform) {
	return render(
		<PlatformProvider platform={platform}>
			<Probe />
		</PlatformProvider>,
	);
}

describe("agentKeys", () => {
	it("keeps the ticked SSH keys that are live and have a private key", () => {
		const entries = [
			sshKey("a", { passphrase: "pw" } as Partial<Entry>),
			sshKey("unticked"),
			sshKey("archived", { archivedAt: 1 }),
			sshKey("public-only", { privateKey: "" } as Partial<Entry>),
			{ id: "login", type: "login", name: "site" } as Entry,
		];

		expect(agentKeys(entries, ["a", "archived", "public-only", "login", "gone"])).toEqual([
			{ id: "a", name: "key a", privateKey: "private a", passphrase: "pw" },
		]);
	});
});

describe("useSshAgent", () => {
	it("offers nothing where the platform has no agent", () => {
		render(
			<PlatformProvider platform={{ storage: {} } as unknown as Platform}>
				<Probe />
			</PlatformProvider>,
		);
		expect(screen.getByTestId("available").textContent).toBe("false");
	});

	it("hands the ticked keys to the agent once the vault is unlocked", async () => {
		h.entries = [sshKey("a"), sshKey("b")];
		const { platform, setKeys } = makePlatform(["a"]);
		mount(platform);

		await waitFor(() =>
			expect(setKeys).toHaveBeenLastCalledWith([
				{ id: "a", name: "key a", privateKey: "private a" },
			]),
		);
		expect(screen.getByTestId("ticked").textContent).toBe("true");
	});

	it("sends nothing while the vault is locked", async () => {
		h.entries = [sshKey("a")];
		h.isLocked = true;
		const { platform, setKeys } = makePlatform(["a"]);
		mount(platform);

		await waitFor(() => expect(screen.getByTestId("ticked").textContent).toBe("true"));
		expect(setKeys).not.toHaveBeenCalled();
	});

	it("a tick is stored on this device and reaches the agent, and so does an untick", async () => {
		h.entries = [sshKey("a")];
		const { platform, setKeys, setMeta } = makePlatform(undefined);
		mount(platform);
		await waitFor(() => expect(screen.getByTestId("available").textContent).toBe("true"));

		act(() => screen.getByText("tick").click());
		await waitFor(() =>
			expect(setKeys).toHaveBeenLastCalledWith([
				{ id: "a", name: "key a", privateKey: "private a" },
			]),
		);
		expect(setMeta).toHaveBeenLastCalledWith(PREF_SSH_AGENT_KEYS, ["a"]);

		act(() => screen.getByText("untick").click());
		await waitFor(() => expect(setKeys).toHaveBeenLastCalledWith([]));
		expect(setMeta).toHaveBeenLastCalledWith(PREF_SSH_AGENT_KEYS, []);
	});

	it("does not send the keys again when an unrelated entry changes", async () => {
		h.entries = [sshKey("a")];
		const { platform, setKeys } = makePlatform(["a"]);
		const view = mount(platform);
		await waitFor(() => expect(setKeys).toHaveBeenCalledTimes(1));

		h.entries = [sshKey("a"), { id: "login", type: "login", name: "site" }];
		view.rerender(
			<PlatformProvider platform={platform}>
				<Probe />
			</PlatformProvider>,
		);

		await act(async () => {});
		expect(setKeys).toHaveBeenCalledTimes(1);
	});

	it("says why a ticked key is not in the agent", async () => {
		h.entries = [sshKey("a")];
		const { platform } = makePlatform(["a"], { a: "wrong-passphrase" });
		mount(platform);

		await waitFor(() => expect(screen.getByTestId("refusal").textContent).toBe("wrong-passphrase"));
	});
});
