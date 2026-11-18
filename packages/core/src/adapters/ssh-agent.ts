/** One ticked SSH key entry, as the platform's agent client needs it. */
export interface SshAgentKey {
	id: string;
	name: string;
	privateKey: string;
	passphrase?: string;
}

/** Why a ticked key is not in the agent. */
export type SshAgentRefusal = "no-agent" | "unsupported-key" | "wrong-passphrase" | "refused";

/**
 * Adds the vault's SSH keys to the ssh-agent already running on this machine, for as long as
 * the vault is unlocked. The platform takes them back out on lock by itself. See docs/ssh-agent.md.
 */
export interface SshAgentAdapter {
	/** Whether there is an agent to add to; false hides the checkbox. */
	isAvailable(): Promise<boolean>;
	/** Make the agent hold exactly these keys of ours. Resolves to the entries left out, by id. */
	setKeys(keys: SshAgentKey[]): Promise<Record<string, SshAgentRefusal>>;
}
