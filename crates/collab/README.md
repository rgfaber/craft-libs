# macula-craft-seam

A collaboration seam for document apps: people on different machines edit one
document, and every change travels as a signed op between peers. No server
holds the document.

What the seam owns, independent of any network:

- **Messages**: text edits, replayable commands, cursor presence, join snapshots.
- **Text merge**: one CRDT document ([yrs](https://crates.io/crates/yrs)) per shared
  document, with one per-author undo over all of it:
  - a flowing **body** of paragraphs with stable ids, where concurrent typing, Enter and joins
    converge without duplicating text;
  - **named bodies**, one per text frame (a slide's text box, say), with the same behaviour;
  - a **keyed register** of opaque keys to app values (a cell, a shape's properties), last
    writer wins;
  - **ordered id lists** (slide order, z-order), where concurrent moves never duplicate an id.

  Ids are opaque strings; `ids::author_id` mints author-scoped numeric ones.
- **Access**: per-document grants (viewer or editor) signed by the host, monotonic revocation,
  open and per-person invite tokens, and realm-membership admission through the
  `MembershipVerifier` trait.
- **Invites**: one copyable line, signed by the host over every field.
- **Contacts**: the people a device has met.
- **The shared session**: `CollabSession` runs one shared document's protocol (join and
  admission, grants and revocation, invites, contacts, snapshot retry, ordering, presence,
  latency) and hands the app the peers' edits to apply. Grants and contacts persist through the
  app's `TextStore`.

What it leaves to an adapter: the `Transport` (how messages travel) and the
issuer and verifiers (how keys sign and check). The Macula mesh adapter is
[macula-craft-collab](https://crates.io/crates/macula-craft-collab). An app
implements `CollabHost` and `DocAdapter` once and applies `CollabSession`'s inbound events to its
document. The Share and Sign in windows (egui) are
[macula-craft-share](https://crates.io/crates/macula-craft-share).

The library name is `macula_craft_seam`; apps that call it `craft_collab` rename the dependency:

```toml
craft-collab = { package = "macula-craft-seam", version = "0.5" }
```

Licensed under MIT or Apache-2.0, at your option.
