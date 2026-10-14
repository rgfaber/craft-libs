# macula-craft-seam

A collaboration seam for document apps: people on different machines edit one
document, and every change travels as a signed op between peers. No server
holds the document.

What the seam owns, independent of any network:

- **Messages**: text edits, replayable commands, cursor presence, join snapshots.
- **Text merge**: paragraph text converges through a CRDT ([yrs](https://crates.io/crates/yrs)).
- **Access**: per-document grants (viewer or editor) signed by the host, monotonic revocation,
  open and per-person invite tokens, and realm-membership admission through the
  `MembershipVerifier` trait.
- **Invites**: one copyable line, signed by the host over every field.
- **Contacts**: the people a device has met.

What it leaves to an adapter: the `Transport` (how messages travel) and the
issuer and verifiers (how keys sign and check). The Macula mesh adapter is
[macula-craft-collab](https://crates.io/crates/macula-craft-collab). An app
implements `CollabHost` and `DocAdapter` once.

The library name is `macula_craft_seam`; apps that call it `craft_collab` rename the dependency:

```toml
craft-collab = { package = "macula-craft-seam", version = "0.1" }
```

Licensed under MIT or Apache-2.0, at your option.
