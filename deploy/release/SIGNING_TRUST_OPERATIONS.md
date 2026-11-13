# Open EPM signing-trust operations

This runbook governs the public trust material used for private Open EPM release
bundles and SDK envelopes. It does not authorize a release. Production remains
blocked until the named rotation owner, exact HTTPS publication URI/channel and
offline custody ceremony have been accepted and exercised.

## Trust boundary

- The offline Ed25519 root private key never enters the repository, release
  bundle, CI worker, registry, application container or operations image.
- The approved trust channel distributes the offline-root public key and the
  minimum accepted trust-policy sequence independently from a candidate.
- The root-signed policy publishes only public release/SDK keys, their exact
  hashes, purposes, validity, overlap state and complete revocation history.
- Release and SDK private keys remain separately protected. Their maximum age
  is 90 days. Old/new public keys may overlap for at most 14 days. Confirmed
  compromise requires policy publication within the selected four-hour SLA.
- Two encrypted offline-root recovery copies are retained in separate secure
  locations. The exact custodians, media, access ceremony and recovery test are
  external acceptance evidence, never source-controlled values.

## Prepare an offline policy input

Work on an isolated offline host. Put only the public signing keys and the input
JSON in one empty working directory. Each `publicKey` is a single local
filename; private release/SDK keys are not inputs.

```json
{
  "format": "openepm-signing-trust-policy-input-v1",
  "sequence": 1,
  "issuedAt": "YYYY-MM-DDTHH:MM:SSZ",
  "expiresAt": "YYYY-MM-DDTHH:MM:SSZ",
  "publicationUri": "https://approved.example/openepm/signing-trust-policy.json",
  "keys": [
    {
      "keyId": "release-key-YYYYqN",
      "publicKey": "release-key-YYYYqN.public.pem",
      "purposes": ["release"],
      "state": "active",
      "validFrom": "YYYY-MM-DDTHH:MM:SSZ",
      "validUntil": "YYYY-MM-DDTHH:MM:SSZ",
      "overlapUntil": null
    },
    {
      "keyId": "sdk-key-YYYYqN",
      "publicKey": "sdk-key-YYYYqN.public.pem",
      "purposes": ["sdk"],
      "state": "active",
      "validFrom": "YYYY-MM-DDTHH:MM:SSZ",
      "validUntil": "YYYY-MM-DDTHH:MM:SSZ",
      "overlapUntil": null
    }
  ],
  "revocations": []
}
```

The policy sequence must strictly increase for every rotation, revocation or
other published change. Exact UTC seconds are required. Policy expiry and each
key lifetime may not exceed 90 days.

## Build and verify the public bundle

Run the source-reviewed tool on the offline host. The output directory must not
already exist.

```sh
python3 scripts/build_openepm_signing_trust_policy.py \
  --input /offline/work/policy-input.json \
  --output /offline/work/public-policy-sequence-N \
  --offline-root-private-key /offline/root/root.private.pem \
  --offline-root-public-key /offline/root/root.public.pem
```

The tool copies only public keys, writes canonical
`signing-trust-policy.json`, signs it as `signing-trust-policy.sig`, and then
self-verifies the root signature, sequence floor, time bounds, key hashes,
purposes, overlap and revocation history. Any failure removes the incomplete
output. It never generates or copies a private key.

Before publication, independently record SHA-256 identities for every output,
verify the policy through `scripts/openepm_signing_trust_policy.py`, and confirm
that the directory contains no private key or unrelated file.

## Rotate

1. Provision new release and/or SDK keys through the accepted custody process.
2. Increment the policy sequence and add their public keys as `active`.
3. Change the previous key to `overlap` and set `overlapUntil` no later than 14
   days after the new policy issue time. Do not extend its 90-day lifetime.
4. Build, independently verify and atomically publish the complete new public
   policy bundle at the approved HTTPS URI.
5. Update the approved release channel's minimum sequence. Confirm a clean host
   accepts the new policy and an upgraded host persists that sequence.
6. After overlap ends, publish another incremented policy that no longer makes
   the old key eligible. Retain its non-secret history as required evidence.

## Emergency revoke

1. Stop signing with the affected private key and restrict its custody path.
2. Provision a replacement key when needed.
3. Increment the policy sequence, set the affected key state to `revoked`, and
   append exactly one revocation record with UTC time, reason and optional
   replacement key ID. Never delete earlier revocation history.
4. Build, verify and atomically publish within four hours of confirmed
   compromise; advance the release-channel minimum sequence immediately.
5. Prove clean install and upgrade reject the revoked key, lower sequences and
   the prior manifest, while accepting artifacts signed by the eligible
   replacement key.
6. Record the external incident/custody evidence without copying credentials,
   private keys or sensitive incident material into the repository.

## Release use and recovery

`epmctl` requires the independently supplied offline-root public key, signed
policy, policy signature and minimum sequence. It verifies the policy and exact
operations-image identity on the host before executing the image verifier. The
highest authenticated sequence is atomically persisted; a lower release-channel
or stored sequence cannot be used to roll back trust.

Recovery must restore the offline root public key and the highest accepted
sequence from accepted operational records. Never restore an older policy as a
rollback mechanism. Loss of all offline-root private-key recovery copies
requires an explicitly accepted trust-root replacement process; it cannot be
repaired by a release signed under the lost root.
