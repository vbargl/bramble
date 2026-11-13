import { describe, expect, it } from "vitest";
import { verifyRemoteRoster } from "./roster";

// Test roster admission enforcement (phase 2): verify that unsigned, unadmitted, and rogue
// device entries are properly rejected. Tests admissionKey pinning (blocker for phase-2).

describe("roster admission enforcement (phase 2)", () => {
	it("rejects unsigned rogue device when signatures required", () => {
		const rogue = {
			id: "rogue",
			publicKey: "rogue-public-key",
			label: "rogue",
			addedAt: 1,
			hlc: { wall: 1, counter: 0, node: "rogue" },
		};
		const result = verifyRemoteRoster(
			{ devices: [], revoked: [] },
			{ devices: [rogue], revoked: [] },
			() => false,
			() => false,
			{ signatures: true, admission: false },
		);
		expect(result.devices).toEqual([]); // Rogue rejected
	});

	it("rejects unadmitted rogue device when admission required", () => {
		// Self-signed but not admitted
		const rogue = {
			id: "rogue",
			publicKey: "rogue-public-key",
			sigKey: "rogue-sig-key",
			sig: "valid-sig",
			label: "rogue",
			addedAt: 1,
			hlc: { wall: 1, counter: 0, node: "rogue" },
		};
		const result = verifyRemoteRoster(
			{ devices: [], revoked: [] },
			{ devices: [rogue], revoked: [] },
			() => true, // signature is valid
			() => false, // no admission
			{ signatures: false, admission: true },
		);
		expect(result.devices).toEqual([]); // Rogue rejected (no admission)
	});

	it("accepts admitted self-signed device when both required", () => {
		const device = {
			id: "device1",
			publicKey: "device-public-key",
			sigKey: "device-sig-key",
			sig: "valid-sig",
			label: "new device",
			addedAt: 1,
			hlc: { wall: 1, counter: 0, node: "device1" },
			admission: { by: "admin", sig: "admission-sig" },
		};
		const result = verifyRemoteRoster(
			{ devices: [], revoked: [] },
			{ devices: [device], revoked: [] },
			() => true, // signature is valid
			() => true, // admission is valid
			{ signatures: true, admission: true },
		);
		expect(result.devices).toHaveLength(1);
		expect(result.devices[0]?.id).toBe("device1");
	});

	it("allows existing device to update with valid signature", () => {
		const existing = {
			id: "device1",
			publicKey: "device-public-key",
			sigKey: "device-sig-key",
			label: "device",
			addedAt: 1,
			hlc: { wall: 1, counter: 0, node: "device1" },
		};
		const updated = {
			...existing,
			label: "renamed device", // label changed (mutable)
			hlc: { wall: 2, counter: 0, node: "device1" }, // timestamp updated
			sig: "new-sig",
		};
		const result = verifyRemoteRoster(
			{ devices: [existing], revoked: [] },
			{ devices: [updated], revoked: [] },
			() => true, // signature is valid
			() => false,
			{ signatures: true, admission: true },
		);
		expect(result.devices).toHaveLength(1);
		expect(result.devices[0]?.label).toBe("renamed device");
	});

	it("rejects established device if sigKey is swapped", () => {
		const existing = {
			id: "device1",
			publicKey: "device-public-key",
			sigKey: "original-sig-key",
			label: "device",
			addedAt: 1,
			hlc: { wall: 1, counter: 0, node: "device1" },
		};
		const swapped = {
			...existing,
			sigKey: "attacker-sig-key", // Key swapped by compromised peer
			sig: "attacker-sig",
		};
		const result = verifyRemoteRoster(
			{ devices: [existing], revoked: [] },
			{ devices: [swapped], revoked: [] },
			() => true, // Attacker's signature is valid
			() => false,
			{ signatures: true, admission: true },
		);
		expect(result.devices).toEqual([]); // Rejection (sigKey mismatch)
	});

	it("rejects established device if admissionKey is swapped", () => {
		const existing = {
			id: "device1",
			publicKey: "device-public-key",
			sigKey: "device-sig-key",
			admissionKey: "original-admission-key",
			label: "device",
			addedAt: 1,
			hlc: { wall: 1, counter: 0, node: "device1" },
		};
		const swapped = {
			...existing,
			admissionKey: "attacker-admission-key", // Swapped by holder of sigKey
			sig: "valid-sig-from-attacker", // Attacker has sigKey and can sign
		};
		const result = verifyRemoteRoster(
			{ devices: [existing], revoked: [] },
			{ devices: [swapped], revoked: [] },
			() => true, // Attacker's signature is valid (they hold sigKey)
			() => false,
			{ signatures: true, admission: true },
		);
		expect(result.devices).toEqual([]); // Rejection (admissionKey pinning blocks swap)
	});

	it("allows admissionKey to be absent on new device", () => {
		const device = {
			id: "device1",
			publicKey: "device-public-key",
			sigKey: "device-sig-key",
			sig: "valid-sig",
			label: "device",
			addedAt: 1,
			hlc: { wall: 1, counter: 0, node: "device1" },
			admission: { by: "admin", sig: "admission-sig" },
			// no admissionKey (optional in early phase)
		};
		const result = verifyRemoteRoster(
			{ devices: [], revoked: [] },
			{ devices: [device], revoked: [] },
			() => true,
			() => true,
			{ signatures: true, admission: true },
		);
		expect(result.devices).toHaveLength(1); // Allowed (admissionKey not yet published)
	});

	it("rejects unapproved admissionKey promotion of an existing device", () => {
		const existing = {
			id: "device1",
			publicKey: "device-public-key",
			sigKey: "device-sig-key",
			label: "device",
			addedAt: 1,
			hlc: { wall: 1, counter: 0, node: "device1" },
			// no admissionKey initially
		};
		const updated = {
			...existing,
			admissionKey: "new-admission-key", // First time admissionKey is published
			sig: "valid-sig",
			hlc: { wall: 2, counter: 0, node: "device1" },
		};
		const result = verifyRemoteRoster(
			{ devices: [existing], revoked: [] },
			{ devices: [updated], revoked: [] },
			() => true,
			() => false,
			{ signatures: true, admission: true },
		);
		expect(result.devices).toHaveLength(0); // A device signature alone is not authority to admit.
	});

	it("rejects revoked device even if properly signed", () => {
		const revoked = {
			id: "device1",
			publicKey: "device-public-key",
			sigKey: "device-sig-key",
			sig: "valid-sig",
			label: "device",
			addedAt: 1,
			hlc: { wall: 1, counter: 0, node: "device1" },
		};
		const result = verifyRemoteRoster(
			{
				devices: [],
				revoked: [{ id: "device1", hlc: { wall: 2, counter: 0, node: "revocation" } }],
			},
			{ devices: [revoked], revoked: [] },
			() => true,
			() => false,
			{ signatures: true, admission: true },
		);
		expect(result.devices).toEqual([]); // Rejection (tombstoned)
	});

	it("accepts mixed: properly signed new device without admission when not required", () => {
		const device = {
			id: "device1",
			publicKey: "device-public-key",
			sigKey: "device-sig-key",
			sig: "valid-sig",
			label: "device",
			addedAt: 1,
			hlc: { wall: 1, counter: 0, node: "device1" },
		};
		const result = verifyRemoteRoster(
			{ devices: [], revoked: [] },
			{ devices: [device], revoked: [] },
			() => true,
			() => false,
			{ signatures: true, admission: false }, // admission NOT required
		);
		expect(result.devices).toHaveLength(1); // Allowed (signature required but not admission)
	});

	it("accepts mixed: unadmitted unsigned device when neither required", () => {
		const device = {
			id: "device1",
			publicKey: "device-public-key",
			label: "device",
			addedAt: 1,
			hlc: { wall: 1, counter: 0, node: "device1" },
		};
		const result = verifyRemoteRoster(
			{ devices: [], revoked: [] },
			{ devices: [device], revoked: [] },
			() => false,
			() => false,
			{ signatures: false, admission: false }, // Neither required (phase 1)
		);
		expect(result.devices).toHaveLength(1); // Allowed (backward compat)
	});

	it("compromised member cannot create rogue with stolen sigKey", () => {
		const legitimate = {
			id: "legitimate",
			publicKey: "legit-public-key",
			sigKey: "legit-sig-key",
			label: "legitimate device",
			addedAt: 1,
			hlc: { wall: 1, counter: 0, node: "legitimate" },
		};
		// Attacker has compromised "compromised" device which has a sigKey
		// They try to create a new rogue entry with their own sigKey (valid signature)
		const rogue = {
			id: "rogue-from-compromised",
			publicKey: "attacker-public-key",
			sigKey: "attacker-sig-key",
			sig: "attacker-valid-sig",
			label: "rogue",
			addedAt: 2,
			hlc: { wall: 2, counter: 0, node: "rogue" },
			// Missing admission: attacker doesn't have the admin's password
		};
		const result = verifyRemoteRoster(
			{ devices: [legitimate], revoked: [] },
			{ devices: [rogue], revoked: [] },
			() => true, // Attacker's self-signature is valid
			() => false, // Attacker cannot produce admission (no password)
			{ signatures: true, admission: true },
		);
		expect(result.devices).toEqual([]); // Rogue blocked (no valid admission)
	});
});

it("rejects promotion of a known signed device with no admission authority", () => {
	const held = {
		id: "member",
		publicKey: "pk",
		sigKey: "sk",
		sig: "valid",
		label: "m",
		addedAt: 1,
		hlc: { wall: 1, counter: 0, node: "m" },
	};
	const remote = { ...held, admissionKey: "attacker-authority" };
	expect(
		verifyRemoteRoster(
			{ devices: [held], revoked: [] },
			{ devices: [remote], revoked: [] },
			() => true,
			() => false,
			{ signatures: true, admission: true },
		).devices,
	).toEqual([]);
});
it("rejects legacy identity replacement without an established authority's admission", () => {
	const held = {
		id: "legacy",
		publicKey: "pk",
		label: "m",
		addedAt: 1,
		hlc: { wall: 1, counter: 0, node: "m" },
	};
	const remote = {
		...held,
		publicKey: "attacker",
		sigKey: "sk",
		sig: "valid",
		admissionKey: "attacker-authority",
	};
	expect(
		verifyRemoteRoster(
			{ devices: [held], revoked: [] },
			{ devices: [remote], revoked: [] },
			() => true,
			() => false,
			{ signatures: true, admission: true },
		).devices,
	).toEqual([]);
});
