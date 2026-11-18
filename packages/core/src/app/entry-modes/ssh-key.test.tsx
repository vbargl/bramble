/** @vitest-environment happy-dom */
import { i18n } from "@lingui/core";
import { I18nProvider } from "@lingui/react";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import type { SshAgentRefusal } from "../../adapters/ssh-agent";
import { type Platform, PlatformProvider } from "../../context/PlatformContext";
import { PREF_SSH_AGENT_KEYS, resetSshAgentCache, useSshAgentSync } from "../../hooks/useSshAgent";
import { sshKeyMode } from "./ssh-key";
import type { EntryDetailBodyProps } from "./types";

const ENTRY = {
	id: "s1",
	type: "ssh-key",
	name: "Server",
	publicKey: "",
	privateKey: "private",
} as unknown as EntryDetailBodyProps["entry"];
const LABEL = "Add to the SSH agent while the vault is unlocked";

vi.mock("../../hooks/useVault", () => ({
	useVault: () => ({ entries: [ENTRY], isLocked: false }),
}));

beforeAll(() => {
	i18n.load("en", {});
	i18n.activate("en");
});

afterEach(() => {
	cleanup();
	resetSshAgentCache();
});

/** The detail body under the same sync the app root runs. */
function Detail() {
	useSshAgentSync();
	return <sshKeyMode.Detail entry={ENTRY} copied={null} copy={() => {}} />;
}

function mount(sshAgent?: { stored?: string[]; refusals?: Record<string, SshAgentRefusal> }) {
	const setMeta = vi.fn(async () => {});
	const platform = {
		storage: { getMeta: vi.fn(async () => sshAgent?.stored), setMeta },
		sshAgent: sshAgent && {
			isAvailable: vi.fn(async () => true),
			setKeys: vi.fn(async () => sshAgent.refusals ?? {}),
		},
	} as unknown as Platform;
	render(
		<I18nProvider i18n={i18n}>
			<PlatformProvider platform={platform}>
				<Detail />
			</PlatformProvider>
		</I18nProvider>,
	);
	return { setMeta };
}

describe("SSH key detail: add to the SSH agent", () => {
	it("offers no checkbox where the platform has no agent", async () => {
		mount();
		await waitFor(() => expect(screen.getByText("Private key")).toBeTruthy());
		expect(screen.queryByLabelText(LABEL)).toBeNull();
	});

	it("ticks the key for this device", async () => {
		const { setMeta } = mount({});
		const box = (await screen.findByLabelText(LABEL)) as HTMLInputElement;
		expect(box.checked).toBe(false);

		fireEvent.click(box);

		await waitFor(() => expect(setMeta).toHaveBeenCalledWith(PREF_SSH_AGENT_KEYS, ["s1"]));
		expect(box.checked).toBe(true);
	});

	it("says why a ticked key did not reach the agent", async () => {
		mount({ stored: ["s1"], refusals: { s1: "unsupported-key" } });

		const alert = await screen.findByRole("alert");
		expect(alert.textContent).toBe(
			"This private key is not in OpenSSH format, so it was not added.",
		);
	});
});
