import { useCallback, useEffect, useMemo, useSyncExternalStore } from "react";
import type { SshAgentKey, SshAgentRefusal } from "../adapters/ssh-agent";
import { usePlatform } from "../context/PlatformContext";
import { type Entry, useVault } from "./useVault";

// Device-scoped and deliberately not synced: which keys this machine's agent holds is a
// decision about this machine. See docs/ssh-agent.md.
export const PREF_SSH_AGENT_KEYS = "pref.sshAgentKeys";

interface State {
	available: boolean;
	/** Ids of the entries ticked on this device. */
	ticked: readonly string[];
	/** The last push's answer: ticked entries the agent does not hold, and why. */
	refusals: Record<string, SshAgentRefusal>;
}

const EMPTY: State = { available: false, ticked: [], refusals: {} };

// Shared rather than per-hook: the sync runs at the app root and the checkbox sits in a route.
let state = EMPTY;
const listeners = new Set<() => void>();
// One push at a time, in the order the changes happened.
let pushes: Promise<unknown> = Promise.resolve();

function publish(next: Partial<State>) {
	state = { ...state, ...next };
	for (const listener of listeners) listener();
}

function subscribe(listener: () => void) {
	listeners.add(listener);
	return () => {
		listeners.delete(listener);
	};
}

/** Test seam: module state outlives a test file otherwise. */
export function resetSshAgentCache() {
	state = EMPTY;
	listeners.clear();
	pushes = Promise.resolve();
}

/** The ticked SSH keys that are live and have a private key to add. */
export function agentKeys(entries: readonly Entry[], ticked: readonly string[]): SshAgentKey[] {
	const wanted = new Set(ticked);
	return entries.flatMap((e) =>
		e.type === "ssh-key" && wanted.has(e.id) && e.privateKey && e.archivedAt === undefined
			? [{ id: e.id, name: e.name, privateKey: e.privateKey, passphrase: e.passphrase }]
			: [],
	);
}

/** Keeps the agent in step with the ticked keys while the vault is unlocked. Mount once. */
export function useSshAgentSync(): void {
	const { sshAgent, storage } = usePlatform();
	const { entries, isLocked } = useVault();
	const { available, ticked } = useSyncExternalStore(subscribe, () => state);

	useEffect(() => {
		if (!sshAgent) return;
		let cancelled = false;
		void Promise.all([sshAgent.isAvailable(), storage.getMeta<string[]>(PREF_SSH_AGENT_KEYS)]).then(
			([isAvailable, stored]) => {
				if (!cancelled)
					publish({ available: isAvailable, ticked: Array.isArray(stored) ? stored : [] });
			},
			(e) => console.warn("[ssh-agent] not available:", e),
		);
		return () => {
			cancelled = true;
		};
	}, [sshAgent, storage]);

	// Compared by content: `entries` is a new array after every vault write, and a write that
	// touched no ticked key must not send private keys across again.
	const wanted = useMemo(() => JSON.stringify(agentKeys(entries, ticked)), [entries, ticked]);

	useEffect(() => {
		if (!sshAgent || !available || isLocked) return;
		const keys = JSON.parse(wanted) as SshAgentKey[];
		pushes = pushes
			.then(() => sshAgent.setKeys(keys))
			.then(
				(refusals) => publish({ refusals }),
				// A lock that won the race refuses the push, which is the right outcome.
				(e) => console.warn("[ssh-agent] keys not updated:", e),
			);
	}, [sshAgent, available, isLocked, wanted]);
}

export interface UseSshAgentKey {
	/** False where there is no agent to add to, which is everything but the desktop app. */
	available: boolean;
	ticked: boolean;
	/** Why the agent does not hold this ticked key, when it does not. */
	refusal: SshAgentRefusal | undefined;
	setTicked(on: boolean): Promise<void>;
}

/** One SSH key entry's "add to the SSH agent" choice on this device. */
export function useSshAgentKey(entryId: string): UseSshAgentKey {
	const { storage } = usePlatform();
	const { available, ticked, refusals } = useSyncExternalStore(subscribe, () => state);
	const isTicked = ticked.includes(entryId);

	const setTicked = useCallback(
		async (on: boolean) => {
			const rest = state.ticked.filter((id) => id !== entryId);
			const next = on ? [...rest, entryId] : rest;
			publish({ ticked: next });
			await storage.setMeta(PREF_SSH_AGENT_KEYS, next);
		},
		[storage, entryId],
	);

	return {
		available,
		ticked: isTicked,
		refusal: isTicked ? refusals[entryId] : undefined,
		setTicked,
	};
}
