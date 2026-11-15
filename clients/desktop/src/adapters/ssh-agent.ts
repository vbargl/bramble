// The client lives in the shell (src-tauri/src/ssh_agent.rs), which also removes the keys on
// lock and on quit, so a closed window cannot leave them behind.

import type { SshAgentAdapter, SshAgentRefusal } from "@core/adapters/ssh-agent";
import { invoke } from "@tauri-apps/api/core";

export const desktopSshAgent: SshAgentAdapter = {
	isAvailable: () => invoke<boolean>("ssh_agent_available"),
	setKeys: (keys) => invoke<Record<string, SshAgentRefusal>>("ssh_agent_set_keys", { keys }),
};
