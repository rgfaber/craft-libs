//! The Share window: the host mints and copies an invite line, approves the
//! people waiting at the door and revokes holders; a joiner pastes an invite
//! and waits for its grant. The mesh wiring is the app's
//! ([`ShareHost::join_invite`]); this window only drives the shared session.

use egui::Context;

use crate::{INVITE_TTL_MS, LoginState, ShareHost, short};

/// Everything the Share window remembers between frames.
#[derive(Default)]
pub struct ShareState {
    pub open: bool,
    /// The paste-in invite line and the display name of the join form.
    pub invite_input: String,
    pub name: String,
    /// The last invite this host minted.
    pub minted: Option<String>,
    /// The invite-a-person form: the person's node id (hex) and name.
    pub for_node: String,
    pub for_name: String,
    /// The last action's outcome, shown under the buttons.
    pub status: Option<String>,
}

/// Why the open invite line is not offered, when it is not: a sealed share's
/// document key goes to named people, one invite each, so a line anyone could
/// copy would be the key handed out in the open. The seam refuses to mint one
/// (`an open invite cannot be sealed: invite people by name`); this window says
/// so before the button is pressed rather than after.
pub fn open_invite_refusal(sealed: bool) -> Option<&'static str> {
    sealed.then_some(
        "This share is sealed: its key goes to named people, one invite each. Use “For one person” below — a line anyone could copy could not carry the key.",
    )
}

/// What a pasted invite asks of the joiner, before Join is pressed: who
/// sent it (and the realm they claim), and for a realm invite which of the
/// joiner's memberships joining presents. The invite's signature is checked
/// at Join; this only reads what it says.
pub fn invite_preview(line: &str) -> Option<Vec<String>> {
    let invite = craft_collab::Invite::decode(line.trim()).ok()?;
    let from = match invite.host_realm.as_deref() {
        Some(realm) => format!("From {} (says they are in {realm}).", invite.host_name),
        None => format!("From {}.", invite.host_name),
    };
    let mut lines = vec![from];
    if invite.member_role.is_some() {
        match invite.member_realm.as_deref() {
            Some(realm) => lines.push(format!("Joining shows {} your membership of {realm}.", invite.host_name)),
            None => lines.push("This realm invite names no realm; it cannot admit you.".into()),
        }
    }
    Some(lines)
}

/// Draws the Share window while `share.open`. Its realm row opens the Sign
/// in window (`login.open`).
pub fn show(ctx: &Context, share: &mut ShareState, login: &mut LoginState, host: &mut dyn ShareHost) {
    if !share.open {
        return;
    }
    let mut open = share.open;
    egui::Window::new("Share").open(&mut open).collapsible(false).default_width(460.0).show(ctx, |ui| {
        if host.collab().is_some() {
            shared_panel(share, host, ui, ctx);
        } else {
            join_form(share, host, ui);
        }
        realm_section(login, host, ui);
        if let Some(msg) = share.status.clone() {
            ui.add_space(4.0);
            ui.label(egui::RichText::new(msg).small());
        }
    });
    share.open = open;
}

/// The realm membership row: tier and renewal state, and the door to the
/// dedicated Sign in window (signing in happens there, not in place).
fn realm_section(login: &mut LoginState, host: &dyn ShareHost, ui: &mut egui::Ui) {
    if !host.hooks().realm_refresh {
        return;
    }
    ui.add_space(6.0);
    ui.separator();
    ui.label(egui::RichText::new("Realm").strong());
    let status = host.realm_status();
    if status["signedIn"].as_bool().unwrap_or(false) {
        let realm = status["realm"].as_str().unwrap_or("");
        let tier = status["tier"].as_str().unwrap_or("");
        let handle = status["handle"].as_str().unwrap_or("");
        let who = if handle.is_empty() { String::new() } else { format!(" — {handle}") };
        ui.label(format!("Signed in to {realm} ({tier}){who}"));
        if let Some(exp) = status["ucanExpiresMs"].as_u64() {
            ui.label(egui::RichText::new(crate::renewal_line(exp)).small());
        }
    } else {
        ui.label(format!("Not signed in to {}.", status["realm"].as_str().unwrap_or("the realm")));
    }
    if ui.button("Manage sign-in…").clicked() {
        login.open = true;
    }
}

fn join_form(share: &mut ShareState, host: &mut dyn ShareHost, ui: &mut egui::Ui) {
    ui.label("Not sharing. Paste the invite line the host sent you:");
    ui.add(egui::TextEdit::multiline(&mut share.invite_input).desired_rows(2).desired_width(f32::INFINITY).hint_text("{\"v\":1,\"doc\":…}"));
    ui.horizontal(|ui| {
        ui.label("Your name:");
        if share.name.is_empty() {
            let author = host.default_name();
            share.name = if author.trim().is_empty() { "Guest".into() } else { author };
        }
        ui.add(egui::TextEdit::singleline(&mut share.name).desired_width(180.0));
    });
    if let Some(lines) = invite_preview(&share.invite_input) {
        for line in lines {
            ui.label(egui::RichText::new(line).small());
        }
    }
    let ready = !share.invite_input.trim().is_empty() && !share.name.trim().is_empty();
    ui.add_enabled_ui(ready, |ui| {
        if ui.button("Join").clicked() {
            if !host.hooks().join_invite {
                share.status = Some("This build has no mesh support.".into());
                return;
            }
            let outcome = host.join_invite(share.invite_input.trim(), share.name.trim());
            share.status = Some(match outcome {
                Ok(()) => "Joining: asking the host for a grant…".into(),
                Err(e) => format!("Join failed: {e}"),
            });
        }
    });
}

fn shared_panel(share: &mut ShareState, host: &mut dyn ShareHost, ui: &mut egui::Ui, ctx: &Context) {
    let host_realm = host.host_realm();
    let Some(collab) = host.collab_mut() else { return };
    // Whether the share is sealed is the session's own answer, and it is the
    // one minting consults: the window offers exactly what the seam would
    // mint, and greys the line exactly when the seam would refuse it.
    let sealed = collab.sealed();
    let stats = collab.stats();
    let doc = stats["doc"].as_str().unwrap_or("").to_string();
    let state = if stats["awaitingGrant"].as_bool().unwrap_or(false) {
        "waiting for the host's grant"
    } else if stats["joined"].as_bool().unwrap_or(false) {
        "joined"
    } else {
        "connecting"
    };
    ui.label(egui::RichText::new(format!("Sharing “{doc}” — {state}")).strong());

    if collab.can_invite() {
        ui.add_space(6.0);
        // A sealed share goes to named people, one invite each: a line anyone
        // holding it could use would be a key handed out in the open, and the
        // seam refuses to mint one. The window greys the button out and says
        // why, rather than letting the person press it and read an error.
        if let Some(why) = open_invite_refusal(sealed) {
            ui.add_enabled_ui(false, |ui| {
                ui.label("Invite line (carries your signed token; valid 24 hours, editor):");
                let _ = ui.button("Mint and copy");
            });
            ui.label(egui::RichText::new(why).small());
        } else {
            ui.label("Invite line (carries your signed token; valid 24 hours, editor):");
            ui.horizontal(|ui| {
                if ui.button("Mint and copy").clicked() {
                    match collab.mint_invite(None, host_realm.as_deref(), craft_collab::Role::Editor, INVITE_TTL_MS) {
                        Ok(line) => {
                            ctx.copy_text(line.clone());
                            share.minted = Some(line);
                            share.status = Some("Invite copied to the clipboard.".into());
                        }
                        Err(e) => share.status = Some(format!("Could not mint an invite: {e}")),
                    }
                }
                if share.minted.is_some()
                    && ui.button("Copy again").clicked()
                    && let Some(line) = share.minted.clone()
                {
                    ctx.copy_text(line);
                    share.status = Some("Invite copied to the clipboard.".into());
                }
            });
            if let Some(line) = share.minted.clone() {
                let mut shown = line;
                ui.add(egui::TextEdit::multiline(&mut shown).desired_rows(2).desired_width(f32::INFINITY).interactive(false));
            }
        }
        ui.add_space(4.0);
        ui.label("For one person (their node id, from contacts or their own message):");
        ui.horizontal(|ui| {
            ui.add(egui::TextEdit::singleline(&mut share.for_node).desired_width(300.0).hint_text("64 hex characters"));
            ui.add(egui::TextEdit::singleline(&mut share.for_name).desired_width(120.0).hint_text("Name"));
            let ready = !share.for_node.trim().is_empty();
            ui.add_enabled_ui(ready, |ui| {
                if ui.button("Mint for them").clicked() {
                    let (node, name) = (share.for_node.clone(), share.for_name.clone());
                    match collab.mint_invite_for(None, host_realm.as_deref(), &node, &name, craft_collab::Role::Editor, INVITE_TTL_MS) {
                        Ok(line) => {
                            ctx.copy_text(line.clone());
                            share.minted = Some(line);
                            share.status = Some("Their invite copied to the clipboard.".into());
                        }
                        Err(e) => share.status = Some(format!("Could not mint their invite: {e}")),
                    }
                }
            });
        });
    }

    let pending = collab.pending();
    if !pending.is_empty() {
        ui.add_space(6.0);
        ui.separator();
        ui.label("Waiting for your yes:");
        for (node, name) in pending {
            ui.horizontal(|ui| {
                ui.label(format!("{name} ({})", short(&node)));
                if ui.button("Approve").clicked() {
                    share.status = Some(match collab.approve(&node) {
                        Ok(()) => format!("Approved {name}."),
                        Err(e) => format!("Approve failed: {e}"),
                    });
                }
            });
        }
    }

    let holders = collab.holders();
    if !holders.is_empty() {
        ui.add_space(6.0);
        ui.separator();
        ui.label("People with access:");
        for holder in holders {
            ui.horizontal(|ui| {
                ui.label(short(&holder));
                if collab.can_invite() && ui.button("Revoke").clicked() {
                    share.status = Some(match collab.revoke(&holder) {
                        Ok(()) => format!("Revoked {}.", short(&holder)),
                        Err(e) => format!("Revoke failed: {e}"),
                    });
                }
            });
        }
    }

    let contacts = collab.contacts();
    if !contacts.is_empty() {
        ui.add_space(6.0);
        ui.separator();
        ui.label("Contacts (people you have met over the mesh):");
        let mut invite_for: Option<(String, String)> = None;
        let mut forget: Option<String> = None;
        for contact in &contacts {
            let label = if contact.name.is_empty() { short(&contact.node) } else { format!("{} ({})", contact.name, short(&contact.node)) };
            ui.horizontal(|ui| {
                ui.label(label);
                if let Some(realm) = &contact.realm {
                    ui.label(egui::RichText::new(realm).small());
                }
                if collab.can_invite() && ui.button("Invite").clicked() {
                    invite_for = Some((contact.node.clone(), contact.name.clone()));
                }
                if ui.button("Forget").clicked() {
                    forget = Some(contact.node.clone());
                }
            });
        }
        if let Some((node, name)) = invite_for {
            match collab.mint_invite_for(None, host_realm.as_deref(), &node, &name, craft_collab::Role::Editor, INVITE_TTL_MS) {
                Ok(line) => {
                    ctx.copy_text(line.clone());
                    share.minted = Some(line);
                    let who = if name.is_empty() { short(&node) } else { name };
                    share.status = Some(format!("Invite for {who} copied to the clipboard."));
                }
                Err(e) => share.status = Some(format!("Could not mint their invite: {e}")),
            }
        }
        if let Some(node) = forget
            && collab.forget_contact(&node)
        {
            share.status = Some(format!("Forgot {}.", short(&node)));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{invite_preview, open_invite_refusal};

    fn invite(member_realm: Option<&str>, host_realm: Option<&str>, realm_invite: bool) -> String {
        craft_collab::Invite {
            v: craft_collab::INVITE_VERSION,
            doc: "doc".into(),
            host: "aa".repeat(32),
            host_key: "bb".repeat(32),
            host_name: "Hana".into(),
            realm: "cc".repeat(32),
            realm_key: String::new(),
            profile: "pq_hybrid".into(),
            seed: "station.example:4433:dd".into(),
            group: String::new(),
            group_grant: String::new(),
            issued_ms: 1,
            expires_ms: 2,
            token: None,
            member_role: realm_invite.then_some(craft_collab::Role::Editor),
            member_realm: member_realm.map(str::to_string),
            host_realm: host_realm.map(str::to_string),
            invitee: None,
            invitee_name: None,
            signature: Vec::new(),
        }
        .encode()
        .expect("encode")
    }

    /// A sealed share offers named invites only, and says why before the
    /// button is pressed (macula-craft-collab#26, threat model decision 5/§4).
    /// The answer is the session's, so the window cannot disagree with minting
    /// (Neptunus r=1).
    #[test]
    fn a_sealed_share_offers_no_open_invite_line() {
        let context = |group: &str| craft_collab::ShareContext {
            realm: "cc".repeat(32),
            realm_key: String::new(),
            seed: "station.example:4433:dd".into(),
            profile: "pq_hybrid".into(),
            group: group.to_string(),
        };
        let mut sealed = craft_collab::CollabSession::host(
            "doc",
            "Hana",
            Box::new(craft_collab::MemoryTransport::pair(&"aa".repeat(32), &"bb".repeat(32)).0),
            &[],
        );
        sealed.set_share_context(context("io.macula/~aa/craft/9f9f9f9f"));
        let why = open_invite_refusal(sealed.sealed()).expect("a sealed share explains itself");
        assert!(why.contains("sealed"), "{why}");
        assert!(why.contains("named people"), "and names the way out: {why}");

        let mut plain = craft_collab::CollabSession::host(
            "doc",
            "Hana",
            Box::new(craft_collab::MemoryTransport::pair(&"aa".repeat(32), &"bb".repeat(32)).0),
            &[],
        );
        plain.set_share_context(context(""));
        assert_eq!(open_invite_refusal(plain.sealed()), None, "a share that does not seal keeps its line");
    }

    /// Fable round 1, item 3: a realm invite says which membership joining
    /// presents, before the person presses Join.
    #[test]
    fn a_realm_invite_says_which_membership_joining_shows() {
        let lines = invite_preview(&invite(Some("net.beam-campus"), Some("io.macula"), true)).expect("an invite");
        assert_eq!(lines[0], "From Hana (says they are in io.macula).");
        assert_eq!(lines[1], "Joining shows Hana your membership of net.beam-campus.");
        let lines = invite_preview(&invite(None, None, false)).expect("an invite");
        assert_eq!(lines, vec!["From Hana.".to_string()], "a token invite asks for no membership");
        assert!(invite_preview("not an invite").is_none());
    }
}
