//! Hands the SSH keys the user ticked to the running ssh-agent while the vault is unlocked, and
//! takes them back on lock. A client of the agent at `SSH_AUTH_SOCK`, not an agent itself.
//! See docs/ssh-agent.md.

use std::{
    collections::HashMap,
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::Mutex,
    time::Duration,
};

use serde::{Deserialize, Serialize};
use ssh_encoding::Encode;
use ssh_key::PrivateKey;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

// draft-miller-ssh-agent, section 5.1.
const SUCCESS: u8 = 6;
const REQUEST_IDENTITIES: u8 = 11;
const IDENTITIES_ANSWER: u8 = 12;
const ADD_IDENTITY: u8 = 17;
const REMOVE_IDENTITY: u8 = 18;

/// A key list from an agent holding thousands of keys still fits; a hostile length does not.
const MAX_ANSWER: usize = 1 << 20;
const IO_TIMEOUT: Duration = Duration::from_secs(2);
/// Ends the comment of every key added here, which is how a key left behind by a crash is
/// recognised as this app's on the next unlock.
const COMMENT_MARK: &str = " (Bramble)";

/// One ticked SSH key entry, as the vault window sends it.
#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase")]
pub struct AgentKey {
    id: String,
    name: String,
    private_key: String,
    #[serde(default)]
    passphrase: Option<String>,
}

/// Why a ticked key is not in the agent. A code, not prose: the window owns the wording.
#[derive(Clone, Copy, Debug, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Refusal {
    /// `SSH_AUTH_SOCK` is unset, or nothing answers there.
    NoAgent,
    /// Not an OpenSSH-format private key this build can read.
    UnsupportedKey,
    /// Encrypted, and the stored passphrase does not open it.
    WrongPassphrase,
    /// The agent answered the add with a failure.
    Refused,
}

/// A key this app put in the agent, and so has to take out again.
struct Held {
    id: String,
    blob: Vec<u8>,
}

static HELD: Mutex<Vec<Held>> = Mutex::new(Vec::new());

fn socket_path() -> Option<PathBuf> {
    std::env::var_os("SSH_AUTH_SOCK")
        .filter(|p| !p.is_empty())
        .map(PathBuf::from)
}

#[cfg(unix)]
fn connect(path: &Path) -> Result<impl Read + Write, Refusal> {
    let stream = std::os::unix::net::UnixStream::connect(path).map_err(|_| Refusal::NoAgent)?;
    stream
        .set_read_timeout(Some(IO_TIMEOUT))
        .and_then(|()| stream.set_write_timeout(Some(IO_TIMEOUT)))
        .map_err(|_| Refusal::NoAgent)?;
    Ok(stream)
}

// Windows reaches its agent through a named pipe, which is not wired.
#[cfg(not(unix))]
fn connect(_path: &Path) -> Result<std::io::Cursor<Vec<u8>>, Refusal> {
    Err(Refusal::NoAgent)
}

fn put_string(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

/// Split a length-prefixed string off the front of `input`.
fn take_string<'a>(input: &mut &'a [u8]) -> Option<&'a [u8]> {
    let len = u32::from_be_bytes(input.get(..4)?.try_into().ok()?) as usize;
    let rest = &input[4..];
    let bytes = rest.get(..len)?;
    *input = &rest[len..];
    Some(bytes)
}

/// Send one request and read its answer, both framed by a 4-byte length.
fn request(agent: &mut (impl Read + Write), body: &[u8]) -> std::io::Result<Vec<u8>> {
    agent.write_all(&(body.len() as u32).to_be_bytes())?;
    agent.write_all(body)?;
    agent.flush()?;
    let mut len = [0u8; 4];
    agent.read_exact(&mut len)?;
    let len = u32::from_be_bytes(len) as usize;
    if len == 0 || len > MAX_ANSWER {
        return Err(std::io::ErrorKind::InvalidData.into());
    }
    let mut answer = vec![0u8; len];
    agent.read_exact(&mut answer)?;
    Ok(answer)
}

/// The agent's keys, as public key blob and comment.
fn identities(agent: &mut (impl Read + Write)) -> Option<Vec<(Vec<u8>, String)>> {
    let answer = request(agent, &[REQUEST_IDENTITIES]).ok()?;
    let mut rest = answer.strip_prefix(&[IDENTITIES_ANSWER])?;
    let count = u32::from_be_bytes(rest.get(..4)?.try_into().ok()?);
    rest = &rest[4..];
    let mut keys = Vec::new();
    for _ in 0..count {
        let blob = take_string(&mut rest)?.to_vec();
        let comment = String::from_utf8_lossy(take_string(&mut rest)?).into_owned();
        keys.push((blob, comment));
    }
    Some(keys)
}

fn succeeded(answer: std::io::Result<Vec<u8>>) -> bool {
    matches!(answer.as_deref(), Ok([SUCCESS]))
}

fn comment_for(name: &str) -> String {
    format!("{name}{COMMENT_MARK}")
}

/// The add request for `key`: its private fields in the layout the key file already uses.
fn add_request(key: &PrivateKey, comment: &str) -> Option<Zeroizing<Vec<u8>>> {
    let data = key.key_data();
    // Sized up front, so growing never leaves a copy of the key behind in freed memory.
    let size = 1 + data.encoded_len().ok()? + 4 + comment.len();
    let mut body = Zeroizing::new(Vec::with_capacity(size));
    body.push(ADD_IDENTITY);
    data.encode(&mut *body).ok()?;
    put_string(&mut body, comment.as_bytes());
    Some(body)
}

/// Read an entry's private key, decrypting it with the stored passphrase when it has one.
fn parse(key: &AgentKey) -> Result<PrivateKey, Refusal> {
    let parsed =
        PrivateKey::from_openssh(key.private_key.trim()).map_err(|_| Refusal::UnsupportedKey)?;
    if !parsed.is_encrypted() {
        return Ok(parsed);
    }
    parsed
        .decrypt(key.passphrase.as_deref().unwrap_or(""))
        .map_err(|e| match e {
            ssh_key::Error::Crypto => Refusal::WrongPassphrase,
            _ => Refusal::UnsupportedKey,
        })
}

/// A ticked key that parsed: what the agent is given, and the blob it is known by afterwards.
struct Ready<'a> {
    key: &'a AgentKey,
    parsed: PrivateKey,
    blob: Vec<u8>,
}

/// Parse the ticked keys, setting aside the ones that cannot be read, by entry id.
fn prepare(wanted: &[AgentKey]) -> (Vec<Ready<'_>>, HashMap<String, Refusal>) {
    let mut ready = Vec::new();
    let mut refused = HashMap::new();
    for key in wanted {
        let parsed = parse(key).and_then(|parsed| {
            let blob = parsed.public_key().to_bytes();
            Ok((parsed, blob.map_err(|_| Refusal::UnsupportedKey)?))
        });
        match parsed {
            Ok((parsed, blob)) => ready.push(Ready { key, parsed, blob }),
            Err(why) => {
                refused.insert(key.id.clone(), why);
            }
        }
    }
    (ready, refused)
}

/// Make the agent hold exactly `ready` of this app's keys, adding the ones it would not take
/// to `refused`.
///
/// A key the agent already has under someone else's comment is left alone and never removed:
/// the user added it themselves.
fn reconcile(
    agent: &mut (impl Read + Write),
    held: &mut Vec<Held>,
    ready: &[Ready],
    refused: &mut HashMap<String, Refusal>,
) {
    let (keep, stale): (Vec<Held>, Vec<Held>) = std::mem::take(held)
        .into_iter()
        .partition(|h| ready.iter().any(|r| r.key.id == h.id && r.blob == h.blob));
    *held = keep;
    for gone in stale {
        // Two entries can hold the same key; it stays while either is still ticked.
        if !ready.iter().any(|r| r.blob == gone.blob) {
            let _ = remove(agent, &gone.blob);
        }
    }

    let missing: Vec<&Ready> = ready
        .iter()
        .filter(|r| !held.iter().any(|h| h.id == r.key.id))
        .collect();
    if missing.is_empty() {
        return;
    }
    let Some(present) = identities(agent) else {
        refused.extend(missing.iter().map(|r| (r.key.id.clone(), Refusal::NoAgent)));
        return;
    };
    for Ready { key, parsed, blob } in missing {
        // Already this app's, through another entry holding the same key.
        let ours = held.iter().any(|h| h.blob == *blob);
        let comment = present.iter().find(|(b, _)| b == blob).map(|(_, c)| c);
        if !ours && comment.is_some_and(|c| !c.ends_with(COMMENT_MARK)) {
            continue;
        }
        if !ours && comment.is_none() {
            let added = add_request(parsed, &comment_for(&key.name))
                .is_some_and(|body| succeeded(request(agent, &body)));
            if !added {
                refused.insert(key.id.clone(), Refusal::Refused);
                continue;
            }
        }
        held.push(Held {
            id: key.id.clone(),
            blob: blob.clone(),
        });
    }
}

/// An agent that answers with a failure no longer has the key, which is the state asked for;
/// only a broken connection is an error.
fn remove(agent: &mut (impl Read + Write), blob: &[u8]) -> std::io::Result<()> {
    let mut body = vec![REMOVE_IDENTITY];
    put_string(&mut body, blob);
    request(agent, &body).map(|_| ())
}

/// Take every key this app added back out of the agent. Called on lock and on quit.
pub fn clear() {
    let mut held = HELD.lock().unwrap();
    if held.is_empty() {
        return;
    }
    let gone = std::mem::take(&mut *held);
    match socket_path()
        .ok_or(Refusal::NoAgent)
        .and_then(|p| connect(&p))
    {
        // Stops at the first broken exchange: a lock must not wait out a timeout per key.
        Ok(mut agent) => {
            if gone.iter().any(|h| remove(&mut agent, &h.blob).is_err()) {
                log::warn!("ssh-agent: the agent stopped answering while keys were removed");
            }
        }
        Err(_) => log::warn!("ssh-agent: no agent to remove {} key(s) from", gone.len()),
    }
}

/// Whether there is an agent to offer the checkbox for.
#[tauri::command]
pub fn ssh_agent_available() -> bool {
    cfg!(unix) && socket_path().is_some()
}

/// Replace the set of keys this app holds in the agent. Answers with the entries left out.
#[tauri::command(async)]
pub fn ssh_agent_set_keys(keys: Vec<AgentKey>) -> Result<HashMap<String, Refusal>, String> {
    if vault_crypto::is_locked() {
        return Err("locked".into());
    }
    // Before taking the lock: decrypting a key is slow, and a vault lock waits on it in `clear`.
    let (ready, mut refused) = prepare(&keys);
    // Held across the whole exchange: a vault lock that lands meanwhile waits, then removes what
    // this added.
    let mut held = HELD.lock().unwrap();
    if vault_crypto::is_locked() {
        return Err("locked".into());
    }
    if ready.is_empty() && held.is_empty() {
        return Ok(refused);
    }
    match socket_path()
        .ok_or(Refusal::NoAgent)
        .and_then(|p| connect(&p))
    {
        Ok(mut agent) => reconcile(&mut agent, &mut held, &ready, &mut refused),
        Err(why) => refused.extend(ready.iter().map(|r| (r.key.id.clone(), why))),
    }
    Ok(refused)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    // Throwaway keys from `ssh-keygen`, used nowhere else.
    const ED25519: &str = include_str!("../fixtures/ssh-agent/ed25519");
    const ED25519_ENCRYPTED: &str = include_str!("../fixtures/ssh-agent/ed25519-encrypted");
    const ECDSA: &str = include_str!("../fixtures/ssh-agent/ecdsa");
    const RSA: &str = include_str!("../fixtures/ssh-agent/rsa");
    const RSA_PEM: &str = include_str!("../fixtures/ssh-agent/rsa-pem");
    const PASSPHRASE: &str = "correct horse";
    const FAILURE: u8 = 5;

    fn entry(id: &str, private_key: &str, passphrase: Option<&str>) -> AgentKey {
        AgentKey {
            id: id.into(),
            name: format!("key {id}"),
            private_key: private_key.into(),
            passphrase: passphrase.map(Into::into),
        }
    }

    /// Parse and reconcile, as the command does.
    fn reconcile(
        agent: &mut (impl Read + Write),
        held: &mut Vec<Held>,
        wanted: &[AgentKey],
    ) -> HashMap<String, Refusal> {
        let (ready, mut refused) = prepare(wanted);
        super::reconcile(agent, held, &ready, &mut refused);
        refused
    }

    fn blob_of(private_key: &str) -> Vec<u8> {
        PrivateKey::from_openssh(private_key)
            .unwrap()
            .public_key()
            .to_bytes()
            .unwrap()
    }

    /// An agent in memory: answers each request as it is written, and records what it was asked.
    #[derive(Default)]
    struct FakeAgent {
        keys: Vec<(Vec<u8>, String)>,
        added: Vec<Vec<u8>>,
        removed: Vec<Vec<u8>>,
        refuse_adds: bool,
        inbox: Vec<u8>,
        outbox: VecDeque<u8>,
    }

    impl FakeAgent {
        fn answer(&mut self, body: &[u8]) -> Vec<u8> {
            match body[0] {
                REQUEST_IDENTITIES => {
                    let mut out = vec![IDENTITIES_ANSWER];
                    out.extend_from_slice(&(self.keys.len() as u32).to_be_bytes());
                    for (blob, comment) in &self.keys {
                        put_string(&mut out, blob);
                        put_string(&mut out, comment.as_bytes());
                    }
                    out
                }
                ADD_IDENTITY if self.refuse_adds => vec![FAILURE],
                ADD_IDENTITY => {
                    self.added.push(body[1..].to_vec());
                    vec![SUCCESS]
                }
                REMOVE_IDENTITY => {
                    let blob = take_string(&mut &body[1..]).unwrap().to_vec();
                    let before = self.keys.len();
                    self.keys.retain(|(b, _)| *b != blob);
                    self.removed.push(blob);
                    vec![if self.keys.len() < before {
                        SUCCESS
                    } else {
                        FAILURE
                    }]
                }
                _ => vec![FAILURE],
            }
        }
    }

    impl Write for FakeAgent {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.inbox.extend_from_slice(buf);
            while self.inbox.len() >= 4 {
                let len = u32::from_be_bytes(self.inbox[..4].try_into().unwrap()) as usize;
                if self.inbox.len() < 4 + len {
                    break;
                }
                let body: Vec<u8> = self.inbox.drain(..4 + len).skip(4).collect();
                let answer = self.answer(&body);
                self.outbox.extend((answer.len() as u32).to_be_bytes());
                self.outbox.extend(answer);
            }
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl Read for FakeAgent {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.outbox.read(buf)
        }
    }

    #[test]
    fn an_ed25519_add_carries_the_seed_and_public_key_under_the_marked_comment() {
        let key = PrivateKey::from_openssh(ED25519).unwrap();
        let pair = key.key_data().ed25519().unwrap();
        let mut expected = vec![ADD_IDENTITY];
        put_string(&mut expected, b"ssh-ed25519");
        put_string(&mut expected, &pair.public.0);
        put_string(&mut expected, &pair.to_bytes());
        put_string(&mut expected, b"laptop (Bramble)");

        assert_eq!(
            *add_request(&key, &comment_for("laptop")).unwrap(),
            expected
        );
    }

    #[test]
    fn ticked_keys_are_added_once_and_removed_when_unticked() {
        let mut agent = FakeAgent::default();
        let mut held = Vec::new();
        let wanted = [
            entry("a", ED25519, None),
            entry("b", ECDSA, None),
            entry("c", RSA, None),
        ];

        assert!(reconcile(&mut agent, &mut held, &wanted).is_empty());
        assert_eq!(agent.added.len(), 3);
        assert!(reconcile(&mut agent, &mut held, &wanted).is_empty());
        assert_eq!(agent.added.len(), 3, "an unchanged set adds nothing");

        assert!(reconcile(&mut agent, &mut held, &wanted[..1]).is_empty());
        assert_eq!(agent.removed, [blob_of(ECDSA), blob_of(RSA)]);
        assert_eq!(held.len(), 1);
    }

    #[test]
    fn an_encrypted_key_needs_its_passphrase() {
        let mut agent = FakeAgent::default();
        let mut held = Vec::new();

        let wrong = [entry("a", ED25519_ENCRYPTED, Some("nope"))];
        assert_eq!(
            reconcile(&mut agent, &mut held, &wrong)["a"],
            Refusal::WrongPassphrase
        );
        let missing = [entry("a", ED25519_ENCRYPTED, None)];
        assert_eq!(
            reconcile(&mut agent, &mut held, &missing)["a"],
            Refusal::WrongPassphrase
        );
        assert!(agent.added.is_empty());

        let right = [entry("a", ED25519_ENCRYPTED, Some(PASSPHRASE))];
        assert!(reconcile(&mut agent, &mut held, &right).is_empty());
        assert_eq!(agent.added.len(), 1);
    }

    #[test]
    fn a_key_in_another_format_is_refused_and_the_rest_still_load() {
        let mut agent = FakeAgent::default();
        let mut held = Vec::new();
        let wanted = [entry("pem", RSA_PEM, None), entry("ok", ED25519, None)];

        let refused = reconcile(&mut agent, &mut held, &wanted);

        assert_eq!(refused.len(), 1);
        assert_eq!(refused["pem"], Refusal::UnsupportedKey);
        assert_eq!(agent.added.len(), 1);
    }

    #[test]
    fn a_key_the_user_added_themselves_is_never_removed() {
        let mut agent = FakeAgent {
            keys: vec![(blob_of(ED25519), "me@laptop".into())],
            ..Default::default()
        };
        let mut held = Vec::new();

        assert!(reconcile(&mut agent, &mut held, &[entry("a", ED25519, None)]).is_empty());
        assert!(reconcile(&mut agent, &mut held, &[]).is_empty());

        assert!(agent.added.is_empty());
        assert!(agent.removed.is_empty());
    }

    #[test]
    fn a_key_left_behind_by_a_crash_is_taken_back() {
        let mut agent = FakeAgent {
            keys: vec![(blob_of(ED25519), comment_for("key a"))],
            ..Default::default()
        };
        let mut held = Vec::new();

        assert!(reconcile(&mut agent, &mut held, &[entry("a", ED25519, None)]).is_empty());
        assert!(agent.added.is_empty());
        assert!(reconcile(&mut agent, &mut held, &[]).is_empty());

        assert_eq!(agent.removed, [blob_of(ED25519)]);
    }

    #[test]
    fn a_key_two_entries_share_stays_while_either_is_ticked() {
        let mut agent = FakeAgent::default();
        let mut held = Vec::new();
        let both = [entry("a", ED25519, None), entry("b", ED25519, None)];

        assert!(reconcile(&mut agent, &mut held, &both).is_empty());
        assert_eq!(agent.added.len(), 1);
        assert!(reconcile(&mut agent, &mut held, &both[1..]).is_empty());
        assert!(agent.removed.is_empty());
        assert!(reconcile(&mut agent, &mut held, &[]).is_empty());

        assert_eq!(agent.removed, [blob_of(ED25519)]);
    }

    #[test]
    fn an_add_the_agent_refuses_is_reported_and_not_held() {
        let mut agent = FakeAgent {
            refuse_adds: true,
            ..Default::default()
        };
        let mut held = Vec::new();

        let refused = reconcile(&mut agent, &mut held, &[entry("a", ED25519, None)]);

        assert_eq!(refused["a"], Refusal::Refused);
        assert!(held.is_empty());
    }

    #[cfg(unix)]
    #[test]
    #[ignore = "needs ssh-agent on PATH"]
    fn a_real_agent_takes_every_supported_key_type() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("agent");
        let mut daemon = std::process::Command::new("ssh-agent")
            .arg("-D")
            .arg("-a")
            .arg(&socket)
            .stdout(std::process::Stdio::null())
            .spawn()
            .unwrap();
        while !socket.exists() {
            std::thread::sleep(Duration::from_millis(20));
        }
        let mut held = Vec::new();
        let wanted = [
            entry("a", ED25519, None),
            entry("b", ED25519_ENCRYPTED, Some(PASSPHRASE)),
            entry("c", ECDSA, None),
            entry("d", RSA, None),
        ];

        let refused = reconcile(&mut connect(&socket).unwrap(), &mut held, &wanted);
        let loaded = identities(&mut connect(&socket).unwrap()).unwrap();
        reconcile(&mut connect(&socket).unwrap(), &mut held, &[]);
        let left = identities(&mut connect(&socket).unwrap()).unwrap();
        daemon.kill().unwrap();
        daemon.wait().unwrap();

        assert!(refused.is_empty(), "{refused:?}");
        let mut blobs: Vec<_> = loaded.iter().map(|(blob, _)| blob.clone()).collect();
        blobs.sort();
        let mut expected: Vec<_> = [ED25519, ED25519_ENCRYPTED, ECDSA, RSA]
            .map(blob_of)
            .to_vec();
        expected.sort();
        assert_eq!(blobs, expected);
        assert!(loaded.iter().all(|(_, c)| c.ends_with(COMMENT_MARK)));
        assert!(left.is_empty());
    }
}
