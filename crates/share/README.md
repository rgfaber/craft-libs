# macula-craft-share

The Share and Sign in windows for Craft apps, in [egui](https://crates.io/crates/egui) 0.36, over
[macula-craft-seam](https://crates.io/crates/macula-craft-seam)'s shared document session.

- **Share**: the host mints and copies invite lines (for anyone holding the line, or for one
  person by node id), approves the people waiting at the door, revokes holders and invites its
  contacts. A joiner pastes an invite, sees who sent it and which membership joining shows, and
  waits for its grant.
- **Sign in**: the realm membership (tier, handle, renewal), the display name, and the portal
  sign-in link with its QR code and confirmation poll.

The windows keep only their own state (`ShareState`, `LoginState`). The app implements
`ShareHost` once: its `CollabSession`, its realm status, and the hooks that need the network
(joining, signing in, the identity's name). A hook the app leaves out greys out its button.

```rust
craft_share::share::show(ctx, &mut share_state, &mut login_state, &mut host);
craft_share::login::show(ctx, &mut login_state, &mut host);
```

The library name is `macula_craft_share`; apps that call it `craft_share` rename the dependency:

```toml
craft-share = { package = "macula-craft-share", version = "0.5" }
```

Licensed under MIT or Apache-2.0, at your option.
