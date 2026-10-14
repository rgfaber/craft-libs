//! The Sign in window: the dedicated realm surface. It shows the realm, the
//! membership tier and handle, and the renewal state; signs in through the
//! portal link with its pending-confirmation poll; names a fresh identity
//! (the startup path never guesses); and refreshes the membership. The
//! Share window's realm row opens this window instead of signing in place,
//! and File ▸ Options carries the same entry.

use egui::Context;

use crate::ShareHost;

#[derive(Default)]
pub struct LoginState {
    pub open: bool,
    /// The person's display-name field, synced from the identity when the
    /// window first shows.
    pub name_input: String,
    pub name_synced: bool,
    /// A sign-in link waiting for the person's confirmation, and when to
    /// poll it next.
    pub link: Option<String>,
    pub link_expires: Option<String>,
    pub next_poll: f64,
    /// The last action's outcome, shown under the sections.
    pub status: Option<String>,
}

/// Draws the Sign in window while `login.open`.
pub fn show(ctx: &Context, login: &mut LoginState, host: &mut dyn ShareHost) {
    if !login.open {
        return;
    }
    if !login.name_synced {
        sync_name(login, host);
    }
    let realm = host.realm_status()["realm"].as_str().unwrap_or("the realm").to_string();
    let mut open = login.open;
    egui::Window::new(format!("Sign in to {realm}")).open(&mut open).collapsible(false).default_width(520.0).show(ctx, |ui| {
        status_section(login, host, ui);
        ui.add_space(6.0);
        ui.separator();
        name_section(login, host, ui);
        ui.add_space(6.0);
        ui.separator();
        sign_in_section(login, host, ui, ctx);
        if let Some(msg) = login.status.clone() {
            ui.add_space(4.0);
            ui.label(egui::RichText::new(msg).small());
        }
    });
    login.open = open;
}

/// Realm, tier, handle and renewal state.
fn status_section(login: &mut LoginState, host: &mut dyn ShareHost, ui: &mut egui::Ui) {
    let status = host.realm_status();
    ui.horizontal(|ui| {
        ui.label(egui::RichText::new("Membership").strong());
        let can_refresh = host.hooks().realm_refresh;
        ui.add_enabled_ui(can_refresh, |ui| {
            if ui.button("Refresh").clicked() {
                login.status = Some(match refresh(login, host) {
                    Ok(()) => "Membership refreshed.".into(),
                    Err(e) => format!("Refresh failed: {e}"),
                });
            }
        });
    });
    if status["signedIn"].as_bool().unwrap_or(false) {
        let realm = status["realm"].as_str().unwrap_or("");
        let tier = status["tier"].as_str().unwrap_or("");
        let handle = status["handle"].as_str();
        let who = match handle {
            Some(h) if !h.is_empty() => format!(" — bound to {h}"),
            _ => String::new(),
        };
        ui.label(format!("Signed in to {realm} ({tier}){who}"));
        if let Some(exp) = status["ucanExpiresMs"].as_u64() {
            ui.label(egui::RichText::new(renewal_line(exp)).small());
        }
    } else {
        ui.label(format!("Not signed in to {}.", status["realm"].as_str().unwrap_or("the realm")));
        ui.label(
            egui::RichText::new("Without a membership this app works standalone; the realm adds a verified identity with your account.").small(),
        );
    }
}

/// The person's display name: asked here for a fresh identity, editable
/// later.
fn name_section(login: &mut LoginState, host: &mut dyn ShareHost, ui: &mut egui::Ui) {
    ui.label(egui::RichText::new("Display name").strong());
    ui.label(egui::RichText::new("How peers see you — beside your keys on this device.").small());
    ui.horizontal(|ui| {
        let enabled = host.hooks().set_identity_name;
        ui.add_enabled_ui(enabled, |ui| {
            ui.add(egui::TextEdit::singleline(&mut login.name_input).desired_width(240.0).hint_text("Your name"));
            if ui.button("Save name").clicked() {
                let name = login.name_input.clone();
                login.status = Some(match save_name(host, &name) {
                    Ok(()) => "Display name saved.".into(),
                    Err(e) => format!("Could not save the name: {e}"),
                });
            }
        });
    });
}

/// The portal link and its pending-confirmation poll.
fn sign_in_section(login: &mut LoginState, host: &mut dyn ShareHost, ui: &mut egui::Ui, ctx: &Context) {
    let can_sign_in = host.hooks().sign_in;
    ui.add_enabled_ui(can_sign_in, |ui| {
        if ui.button("Sign in").clicked() {
            login.status = Some(match start_sign_in(login, host) {
                Ok(()) => "Waiting for the confirmation — open the link on any device.".into(),
                Err(e) => format!("Sign in failed: {e}"),
            });
        }
    });
    if let Some(link) = login.link.clone() {
        ui.add_space(4.0);
        ui.label("Open this link and confirm with your account:");
        let mut shown = link.clone();
        ui.add(egui::TextEdit::singleline(&mut shown).desired_width(f32::INFINITY).interactive(false));
        if let Some(expires) = login.link_expires.as_deref() {
            ui.label(egui::RichText::new(format!("The link expires {expires}.")).small());
        }
        qr_image(ui, &link);
        ui.horizontal(|ui| {
            if ui.button("Copy link").clicked() {
                ctx.copy_text(link.clone());
                login.status = Some("Link copied.".into());
            }
            if ui.button("Check now").clicked() {
                login.next_poll = 0.0;
            }
        });
        ui.label(egui::RichText::new("Waiting for the confirmation…").small());
        if now_s() >= login.next_poll {
            login.next_poll = now_s() + 4.0;
            match check_sign_in(login, host) {
                Ok(Some(done)) => {
                    login.link = None;
                    login.link_expires = None;
                    login.status = Some(done);
                }
                Ok(None) => {}
                Err(e) => {
                    login.link = None;
                    login.link_expires = None;
                    login.status = Some(format!("Sign in failed: {e}"));
                }
            }
        }
        ctx.request_repaint_after(std::time::Duration::from_secs(3));
    }
}

/// Draws the link's QR (the qr module's matrix; the drawing is per
/// app): white ground, black modules, a four-module quiet zone, scaled to
/// fit the window.
fn qr_image(ui: &mut egui::Ui, link: &str) {
    const SIZE: f32 = 208.0;
    const QUIET: usize = 4;
    match crate::qr::matrix(link) {
        Ok(matrix) => {
            let total = (matrix.width + 2 * QUIET) as f32;
            let cell = SIZE / total;
            let (rect, _) = ui.allocate_exact_size(egui::vec2(SIZE, SIZE), egui::Sense::hover());
            let painter = ui.painter();
            painter.rect_filled(rect, 2.0, egui::Color32::WHITE);
            for row in 0..matrix.width {
                for col in 0..matrix.width {
                    if matrix.dark(row, col) {
                        let x = rect.min.x + (col + QUIET) as f32 * cell;
                        let y = rect.min.y + (row + QUIET) as f32 * cell;
                        painter.rect_filled(
                            egui::Rect::from_min_size(egui::pos2(x, y), egui::vec2(cell + 0.5, cell + 0.5)),
                            0.0,
                            egui::Color32::BLACK,
                        );
                    }
                }
            }
        }
        Err(e) => {
            ui.label(egui::RichText::new(format!("QR unavailable: {e}")).small());
        }
    }
}

/// "Membership UCAN valid for N more minutes."
pub fn renewal_line(expires_ms: u64) -> String {
    let now_ms = (now_s() * 1_000.0) as u64;
    let left_min = if expires_ms > now_ms { (expires_ms - now_ms) / 60_000 } else { 0 };
    format!("Membership UCAN valid for {left_min} more minutes.")
}

fn now_s() -> f64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs_f64()).unwrap_or(0.0)
}

fn sync_name(login: &mut LoginState, host: &mut dyn ShareHost) {
    login.name_synced = true;
    if !host.hooks().identity_name {
        return;
    }
    if let Ok(v) = host.identity_name()
        && let Some(name) = v["name"].as_str()
    {
        login.name_input = name.to_string();
    }
}

fn save_name(host: &mut dyn ShareHost, name: &str) -> Result<(), String> {
    if !host.hooks().set_identity_name {
        return Err("this build has no identity support".into());
    }
    host.set_identity_name(name).map(|_| ())
}

fn refresh(_login: &mut LoginState, host: &mut dyn ShareHost) -> Result<(), String> {
    if !host.hooks().realm_refresh {
        return Err("this build has no realm support".into());
    }
    host.realm_refresh().map(|_| ())
}

fn start_sign_in(login: &mut LoginState, host: &mut dyn ShareHost) -> Result<(), String> {
    if !host.hooks().sign_in {
        return Err("this build has no realm support".into());
    }
    let started = host.sign_in()?;
    let link = started["joinUrl"].as_str().ok_or_else(|| "the realm answered no link".to_string())?;
    login.link = Some(link.to_string());
    login.link_expires = started["expiresAt"].as_str().map(str::to_string);
    login.next_poll = now_s() + 4.0;
    Ok(())
}

/// `Ok(Some(note))` when the session finished (confirmed or expired),
/// `Ok(None)` while it waits.
fn check_sign_in(_login: &mut LoginState, host: &mut dyn ShareHost) -> Result<Option<String>, String> {
    if !host.hooks().sign_in_check {
        return Err("this build has no realm support".into());
    }
    let status = host.sign_in_check()?;
    match status["status"].as_str() {
        Some("pending") | None => Ok(None),
        Some("confirmed") => Ok(Some("Signed in — the realm membership is stored.".into())),
        Some("expired") => Ok(Some("The sign-in link expired; start again.".into())),
        Some("none") => Ok(Some("No sign-in is waiting.".into())),
        Some(other) => Ok(Some(format!("Sign-in state: {other}"))),
    }
}
