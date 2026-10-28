# macula-craft-share

The Share and Sign in windows for Craft apps, in [egui](https://crates.io/crates/egui) 0.37, over
[macula-craft-seam](https://crates.io/crates/macula-craft-seam)'s shared document session.

- **Share**: the host mints and copies invite lines, approves the people waiting at the door, revokes
  holders and invites its contacts. On a sealed share (every released Craft build) an invite goes to
  one named person, one line each, because the share's key travels with the invite and a line anyone
  could copy could not carry it: the open line is greyed out with the reason rather than offered and
  refused. A share that does not seal keeps its open line. A joiner pastes an invite, sees who sent
  it and which membership joining shows, and waits for its grant.
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
craft-share = { package = "macula-craft-share", version = "0.7" }
```

Licensed under MIT or Apache-2.0, at your option.
