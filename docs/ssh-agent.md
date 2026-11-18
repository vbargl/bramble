# Adding SSH keys to the ssh-agent

The desktop app can hand an SSH key entry's private key to the ssh-agent already running on the
machine, for as long as the vault is unlocked. It is a client of that agent. It is not the SSH
agent planned in [desktop-port.md](desktop-port.md), which would serve keys itself and approve
each signature; the two do not depend on each other.

## Behaviour

- An SSH key entry shows a checkbox, **Add to the SSH agent while the vault is unlocked**, where
  an agent is reachable (`SSH_AUTH_SOCK` is set). Everywhere else the checkbox is absent.
- The choice is stored per device, in the `pref.sshAgentKeys` metadata key, as a list of entry
  ids. It is not part of the entry and does not sync: which keys a machine's agent holds is a
  decision about that machine, and a client that does not know the field cannot drop it on edit.
- On unlock, and whenever a ticked entry changes, the window sends the ticked keys to the shell
  (`ssh_agent_set_keys`), which makes the agent hold exactly that set of the app's keys.
- On lock (manual or auto-lock) and on quit, the shell removes every key it added. This happens
  in the shell, so it does not depend on a window being open.
- Archived entries and entries without a private key are skipped.

## What the app removes

Only keys it added. Each one is added under a comment ending in ` (Bramble)`.

- A key the agent already holds under another comment was added by the user (`ssh-add`). It is
  left alone and never removed.
- A key the agent already holds under the app's comment was left behind by a crash. It is taken
  over, and removed on the next lock.
- A key shared by two ticked entries stays until both are unticked.

## Supported keys

OpenSSH-format private keys (`BEGIN OPENSSH PRIVATE KEY`): Ed25519, ECDSA and RSA, with or without
a passphrase. An encrypted key is decrypted with the entry's passphrase before it goes to the
agent, which is how `ssh-add` hands keys over as well. Older PEM and PKCS#8 keys are not read; the
entry then says why its key was not added. RustCrypto's `ssh-key` does the parsing and the
decryption, with none of its signing features: the agent signs.

## Limits

- Unix sockets only. Windows reaches its agent through a named pipe, which is not wired.
- No per-key constraints (confirm each use, lifetime).
- If the app is killed, its keys stay in the agent until the next unlock and lock, or until the
  agent restarts.
