//! Document text merge: one CRDT text for the body, every paragraph opened
//! by a leader character whose attributes carry its stable id (and its
//! paragraph properties, app-encoded), so concurrent typing, Enter and
//! paragraph joins converge without duplicating or losing text. Pressing
//! Enter inserts a leader; joining two paragraphs deletes one; per-author
//! undo is one yrs undo manager over the whole text, scoped to this
//! author's origin.
//!
//! Paragraphs outside the body (an app's table cells, say) keep a text of
//! their own, keyed by their id, exactly as before.
//!
//! The same document holds a keyed register: opaque string keys to app
//! values (a spreadsheet's cells, a shape's properties). Each key holds one
//! value; when two authors write a key at once, every replica keeps the same
//! one. Register writes travel and undo exactly like text edits.
//!
//! Named bodies (one per text frame of a slide, say) behave exactly like
//! the body, each under a root of its own. Paragraph ids are unique across
//! the document, so the paragraph edits find the body that holds one.
//!
//! Ordered id lists (slide order, z-order) hold opaque ids. A move is a
//! CRDT move, so two authors moving one id at once leave it in one place;
//! two authors inserting one id at once leave two copies in the CRDT, and
//! every replica reads the first. Lists undo per author like the rest.
//!
//! An inline object (a comment's anchor, a bookmark, a field) is one
//! [`OBJECT_CHAR`] in the text whose `obj` attribute holds the app's
//! payload, the way a leader carries its paragraph id: it takes the bytes
//! the app's own object character takes, travels, splits, joins and undoes
//! like text, and concurrent typing around it lands where the author typed.
//! An object is never re-tagged in place: changing one is removing it and
//! inserting the new one, so its payload never moves to another item.
//!
//! Offsets are bytes (yrs's default), which matches the apps' byte offsets.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::{Arc, Mutex};

use yrs::types::Attrs;
use yrs::undo::{Options as UndoOptions, UndoManager};
use yrs::updates::decoder::Decode;
use yrs::{
    Any, Array, ArrayRef, Assoc, Doc, GetString, IndexedSequence, Map, MapRef, Observable, Options, Origin, Out, ReadTxn, StickyIndex, Subscription,
    Text, TextRef, Transact, Update,
};

/// The body text's root name (paragraph ids are numeric strings, so it never
/// names a paragraph).
const BODY: &str = "craft-body";
/// The leader's attribute naming its paragraph.
const PID: &str = "pid";
/// The leader's attribute holding the paragraph's properties, app-encoded.
const PROPS: &str = "props";
/// The leader character itself: one byte, told apart from a typed line
/// break by its `pid` attribute.
const LEADER: &str = "\n";
/// An inline object's attribute: the app's payload.
const OBJ: &str = "obj";
/// The character an inline object is in the text (U+FFFC, three bytes).
pub const OBJECT_CHAR: char = '\u{FFFC}';
/// The keyed register's root name.
const REGISTER: &str = "craft-register";
/// A named body's root name is this prefix and its name (an app's text
/// frame, say); the unnamed body keeps [`BODY`].
const NAMED_BODY: &str = "craft-body:";
/// An ordered id list's root name is this prefix and its name.
const LIST: &str = "craft-list:";

/// One paragraph of the body, in order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BodyParagraph {
    /// The stable paragraph id.
    pub para: String,
    /// Its text, without the leader.
    pub text: String,
    /// Its properties as the app encoded them when the paragraph was made.
    pub props: Option<String>,
}

/// Where a paragraph sits in the body: its leader, then its text.
#[derive(Clone, Debug)]
struct Slot {
    /// The named body holding it, `None` for the unnamed body.
    body: Option<String>,
    para: String,
    leader_at: u32,
    text: String,
    props: Option<String>,
}

impl Slot {
    fn start(&self) -> u32 {
        self.leader_at + LEADER.len() as u32
    }
}

/// The text CRDT for one document.
pub struct TextMerge {
    doc: Doc,
    /// The body text, held so no read path ever needs a write transaction
    /// (yrs's get-or-insert takes one, and would deadlock under a read).
    body: TextRef,
    /// This author's transaction origin: what the undo manager tracks.
    origin: Origin,
    undo: UndoManager<()>,
    /// Paragraphs outside the body whose own texts the undo manager covers.
    outside: HashSet<String>,
    /// The keyed register, under the same undo manager.
    register: MapRef,
    /// Register keys changed since the app last asked: every write, local,
    /// remote, undone or loaded, lands here.
    changed: Arc<Mutex<BTreeSet<String>>>,
    _watch: Subscription,
    /// Named bodies and lists this author has touched, so under undo.
    scoped: HashSet<String>,
    /// What each named body and list read when the app last asked what
    /// changed.
    seen: HashMap<String, String>,
    /// Inside [`TextMerge::begin_step`]: every write until
    /// [`TextMerge::end_step`] is one undo step.
    in_step: bool,
}

impl TextMerge {
    /// A merge for one author (whose edits it can undo).
    pub fn new(author: &str) -> Self {
        let doc = Doc::with_options(Options::default());
        let body = doc.get_or_insert_text(BODY);
        let origin = Origin::from(author.to_string());
        // Built in full: yrs has no default undo options on wasm, and its own
        // clock panics without a system time. Ours reads 0 there.
        let options = UndoOptions {
            capture_timeout_millis: 500,
            tracked_origins: HashSet::from([origin.clone()]),
            capture_transaction: None,
            timestamp: std::sync::Arc::new(crate::session::now_ms),
        };
        let mut undo = UndoManager::with_scope_and_options(&doc, &body, options);
        let register = doc.get_or_insert_map(REGISTER);
        undo.expand_scope(&register);
        let changed = Arc::new(Mutex::new(BTreeSet::new()));
        let sink = changed.clone();
        let _watch = register.observe(move |txn, event| {
            if let Ok(mut keys) = sink.lock() {
                keys.extend(event.keys(txn).keys().map(|k| k.to_string()));
            }
        });
        TextMerge {
            doc,
            body,
            origin,
            undo,
            outside: HashSet::new(),
            register,
            changed,
            _watch,
            scoped: HashSet::new(),
            seen: HashMap::new(),
            in_step: false,
        }
    }

    /// Starts one undo step: every write this author makes until
    /// [`TextMerge::end_step`] (text, register, bodies, lists) is taken back
    /// by one [`TextMerge::undo_local`]. An app whose one command touches
    /// several parts of the document (a shape's record, its text, its place
    /// in a list) brackets the command with these. Without a step, each edit,
    /// split, join, bold, clear and list change is its own undo step, and
    /// register writes close together share one.
    pub fn begin_step(&mut self) {
        self.undo.reset();
        self.in_step = true;
    }

    /// Ends the step [`TextMerge::begin_step`] began.
    pub fn end_step(&mut self) {
        self.undo.reset();
        self.in_step = false;
    }

    /// Ends the current undo capture, unless a step is open.
    fn end_capture(&mut self) {
        if !self.in_step {
            self.undo.reset();
        }
    }

    /// Writes `value` under `key` as this author: the update to broadcast,
    /// `None` when the key already holds that value.
    pub fn register_set(&mut self, key: &str, value: &str) -> Option<Vec<u8>> {
        if self.register_get(key).as_deref() == Some(value) {
            return None;
        }
        let mut txn = self.doc.transact_mut_with(self.origin.clone());
        self.register.insert(&mut txn, key, value);
        Some(txn.encode_update_v1())
    }

    /// Seeds the register with what the document already holds when it is first shared: written
    /// with no author, so no one's undo ever takes it back (an undo of a later edit returns to
    /// it). The update to broadcast, `None` when there is nothing to seed.
    pub fn register_seed(&mut self, entries: &[(String, String)]) -> Option<Vec<u8>> {
        if entries.is_empty() {
            return None;
        }
        let mut txn = self.doc.transact_mut();
        for (key, value) in entries {
            self.register.insert(&mut txn, key.as_str(), value.as_str());
        }
        Some(txn.encode_update_v1())
    }

    /// Removes `key` as this author: the update to broadcast, `None` when
    /// the key was not there.
    pub fn register_remove(&mut self, key: &str) -> Option<Vec<u8>> {
        self.register_get(key)?;
        let mut txn = self.doc.transact_mut_with(self.origin.clone());
        self.register.remove(&mut txn, key);
        Some(txn.encode_update_v1())
    }

    /// The value under `key`.
    pub fn register_get(&self, key: &str) -> Option<String> {
        let txn = self.doc.transact();
        self.register.get(&txn, key).and_then(|v| out_text(&v))
    }

    /// Every key and value, sorted by key.
    pub fn register_entries(&self) -> Vec<(String, String)> {
        let txn = self.doc.transact();
        let mut entries: Vec<(String, String)> = self.register.iter(&txn).filter_map(|(k, v)| out_text(&v).map(|v| (k.to_string(), v))).collect();
        entries.sort();
        entries
    }

    /// The register keys changed since the last call, sorted: what the app
    /// re-reads after applying a peer's update, an undo or a snapshot (its
    /// own writes are listed too).
    pub fn register_changed(&mut self) -> Vec<String> {
        self.changed.lock().map(|mut keys| std::mem::take(&mut *keys).into_iter().collect()).unwrap_or_default()
    }

    fn body(&self) -> TextRef {
        self.body.clone()
    }

    /// A paragraph outside the body: its own text, under undo too.
    fn outside_text(&mut self, para: &str) -> TextRef {
        let text = self.doc.get_or_insert_text(para.to_string());
        if self.outside.insert(para.to_string()) {
            self.undo.expand_scope(&text);
        }
        text
    }

    /// The unnamed body's paragraphs.
    fn slots<T: ReadTxn>(&self, txn: &T) -> Vec<Slot> {
        slots_in(&self.body, None, txn)
    }

    /// The names of the named bodies (or lists, by prefix) this document holds.
    fn root_names(&self, prefix: &str) -> Vec<String> {
        let txn = self.doc.transact();
        let mut names: Vec<String> = txn.root_refs().filter_map(|(name, _)| name.strip_prefix(prefix).map(str::to_string)).collect();
        names.sort();
        names
    }

    /// A named body's text (made when first named; never under a transaction).
    fn named_ref(&self, name: &str) -> TextRef {
        self.doc.get_or_insert_text(format!("{NAMED_BODY}{name}"))
    }

    /// The text a slot's paragraph lives in.
    fn text_of(&self, body: Option<&str>) -> TextRef {
        match body {
            None => self.body(),
            Some(name) => self.named_ref(name),
        }
    }

    /// Puts a named body or list under this author's undo the first time
    /// it is touched locally.
    fn scope<T: AsRef<yrs::branch::Branch>>(&mut self, root: &str, r: &T) {
        if self.scoped.insert(root.to_string()) {
            self.undo.expand_scope(r);
        }
    }

    /// The text a local edit to `slot` goes to, under undo.
    fn edit_text(&mut self, body: Option<&str>) -> TextRef {
        let text = self.text_of(body);
        if let Some(name) = body {
            self.scope(&format!("{NAMED_BODY}{name}"), &text);
        }
        text
    }
}

/// A body's paragraphs, in order.
fn slots_in<T: ReadTxn>(text: &TextRef, body: Option<&str>, txn: &T) -> Vec<Slot> {
    {
        let mut slots: Vec<Slot> = Vec::new();
        let mut pos = 0u32;
        for chunk in text.diff(txn, |_| ()) {
            let Some(s) = out_text(&chunk.insert) else { continue };
            let attrs = chunk.attributes.as_deref();
            match attrs.and_then(|a| a.get(PID)).and_then(any_string) {
                Some(pid) => {
                    let props = attrs.and_then(|a| a.get(PROPS)).and_then(any_string);
                    // Each leader is its own paragraph (adjacent leaders
                    // never share a chunk: their ids differ).
                    for (i, _) in s.char_indices() {
                        slots.push(Slot {
                            body: body.map(str::to_string),
                            para: pid.clone(),
                            leader_at: pos + i as u32,
                            text: String::new(),
                            props: props.clone(),
                        });
                    }
                }
                None => {
                    // Text belongs to the paragraph whose leader precedes it;
                    // anything before the first leader has no paragraph.
                    if let Some(last) = slots.last_mut() {
                        last.text.push_str(&s);
                    }
                }
            }
            pos += s.len() as u32;
        }
        slots
    }
}

impl TextMerge {
    /// The slot of a paragraph in whichever body holds it: paragraph ids are
    /// unique across the document.
    fn slot(&self, para: &str) -> Option<Slot> {
        if let Some(slot) = self.slots(&self.doc.transact()).into_iter().find(|s| s.para == para) {
            return Some(slot);
        }
        self.root_names(NAMED_BODY).into_iter().find_map(|name| {
            let text = self.named_ref(&name);
            let txn = self.doc.transact();
            slots_in(&text, Some(&name), &txn).into_iter().find(|s| s.para == para)
        })
    }

    /// Whether a body (the unnamed one or a named one) holds this paragraph.
    pub fn in_body(&self, para: &str) -> bool {
        self.slot(para).is_some()
    }

    /// The body's paragraphs, in order.
    pub fn body_paragraphs(&self) -> Vec<BodyParagraph> {
        let txn = self.doc.transact();
        self.slots(&txn).into_iter().map(|s| BodyParagraph { para: s.para, text: s.text, props: s.props }).collect()
    }

    /// Seeds an empty body with the document's paragraphs (the sharing
    /// host does this once; joiners get it in the snapshot). Not undoable.
    /// The update to broadcast, `None` when the body already has content.
    pub fn seed_body(&mut self, paras: &[BodyParagraph]) -> Option<Vec<u8>> {
        if !self.body_paragraphs().is_empty() || paras.is_empty() {
            return None;
        }
        Some(seed_into(&self.doc, &self.body, paras))
    }

    /// The named bodies this document holds, sorted (a peer's new body shows
    /// once its first update is applied).
    pub fn body_names(&self) -> Vec<String> {
        self.root_names(NAMED_BODY)
    }

    /// A named body's paragraphs, in order; empty for a body never written.
    /// An empty body is not a deleted one: whether its frame exists is the
    /// app's to say (a list or the register), since a peer still typing into
    /// a body another author cleared keeps that typing.
    pub fn named_body_paragraphs(&self, name: &str) -> Vec<BodyParagraph> {
        if !self.body_names().iter().any(|n| n == name) {
            return Vec::new();
        }
        let text = self.named_ref(name);
        let txn = self.doc.transact();
        slots_in(&text, Some(name), &txn).into_iter().map(|s| BodyParagraph { para: s.para, text: s.text, props: s.props }).collect()
    }

    /// Seeds an empty named body (a frame that existed before sharing, or
    /// one this author just made) with its paragraphs. Not undoable, as
    /// [`TextMerge::seed_body`]. The update to broadcast, `None` when the body
    /// already has content or `paras` is empty.
    pub fn seed_named_body(&mut self, name: &str, paras: &[BodyParagraph]) -> Option<Vec<u8>> {
        if paras.is_empty() || !self.named_body_paragraphs(name).is_empty() {
            return None;
        }
        let text = self.edit_text(Some(name));
        Some(seed_into(&self.doc, &text, paras))
    }

    /// Empties a named body as this author (its frame was deleted): the
    /// update to broadcast, `None` when it was already empty. Undoable. A
    /// peer typing into it at the same moment keeps those characters in the
    /// CRDT, but with no paragraph to hold them the body reads empty on every
    /// replica; an undo of the clear brings the paragraphs back around them.
    pub fn clear_named_body(&mut self, name: &str) -> Option<Vec<u8>> {
        if !self.body_names().iter().any(|n| n == name) {
            return None;
        }
        let text = self.edit_text(Some(name));
        let len = text.len(&self.doc.transact());
        if len == 0 {
            return None;
        }
        self.end_capture();
        let mut txn = self.doc.transact_mut_with(self.origin.clone());
        text.remove_range(&mut txn, 0, len);
        Some(txn.encode_update_v1())
    }

    /// The named bodies whose paragraphs changed since the last call, sorted:
    /// local edits, a peer's, an undo or a snapshot.
    pub fn bodies_changed(&mut self) -> Vec<String> {
        let now: Vec<(String, String)> =
            self.body_names().into_iter().map(|name| (format!("{NAMED_BODY}{name}"), format!("{:?}", self.named_body_paragraphs(&name)))).collect();
        self.changed_since(now, NAMED_BODY)
    }

    /// The roots under `prefix` whose reading differs from the last one seen.
    fn changed_since(&mut self, now: Vec<(String, String)>, prefix: &str) -> Vec<String> {
        let mut changed = Vec::new();
        for (root, reading) in now {
            if self.seen.get(&root) != Some(&reading) {
                changed.push(root.trim_start_matches(prefix).to_string());
                self.seen.insert(root, reading);
            }
        }
        changed
    }

    /// The ids of a list, in order. An id that two authors inserted at once
    /// is there twice in the CRDT; every replica reads its first occurrence
    /// only.
    pub fn list_ids(&self, name: &str) -> Vec<String> {
        if !self.root_names(LIST).iter().any(|n| n == name) {
            return Vec::new();
        }
        let list = self.list_ref(name);
        let txn = self.doc.transact();
        let mut seen = HashSet::new();
        list.iter(&txn).filter_map(|v| out_text(&v)).filter(|id| seen.insert(id.clone())).collect()
    }

    /// The lists this document holds, sorted.
    pub fn list_names(&self) -> Vec<String> {
        self.root_names(LIST)
    }

    /// Seeds an empty list with what the document already holds (no one's
    /// undo takes it back). The update to broadcast, `None` when the list
    /// has ids already or `ids` is empty.
    pub fn list_seed(&mut self, name: &str, ids: &[String]) -> Option<Vec<u8>> {
        if ids.is_empty() || !self.list_ids(name).is_empty() {
            return None;
        }
        let list = self.edit_list(name);
        let mut txn = self.doc.transact_mut();
        for (i, id) in ids.iter().enumerate() {
            list.insert(&mut txn, i as u32, id.as_str());
        }
        Some(txn.encode_update_v1())
    }

    /// Inserts `id` at `index` (clamped) as this author: the update, `None`
    /// when this replica already lists it.
    pub fn list_insert(&mut self, name: &str, index: u32, id: &str) -> Option<Vec<u8>> {
        let ids = self.list_ids(name);
        if ids.iter().any(|i| i == id) {
            return None;
        }
        let list = self.edit_list(name);
        let raw = self.raw_index(&list, &ids, index);
        self.end_capture();
        let mut txn = self.doc.transact_mut_with(self.origin.clone());
        list.insert(&mut txn, raw, id);
        Some(txn.encode_update_v1())
    }

    /// Removes `id` (every copy of it) as this author: the update, `None`
    /// when it is not listed.
    pub fn list_remove(&mut self, name: &str, id: &str) -> Option<Vec<u8>> {
        if !self.list_ids(name).iter().any(|i| i == id) {
            return None;
        }
        let list = self.edit_list(name);
        let at: Vec<u32> = {
            let txn = self.doc.transact();
            list.iter(&txn).enumerate().filter(|(_, v)| out_text(v).as_deref() == Some(id)).map(|(i, _)| i as u32).collect()
        };
        self.end_capture();
        let mut txn = self.doc.transact_mut_with(self.origin.clone());
        for i in at.into_iter().rev() {
            list.remove(&mut txn, i);
        }
        Some(txn.encode_update_v1())
    }

    /// Moves `id` so it reads at `to` (clamped) as this author: the update,
    /// `None` when it is not listed or already there. Any other copy of the
    /// id (two authors inserted it at once) goes in the same change, so the
    /// moved one is the one every replica reads.
    pub fn list_move(&mut self, name: &str, id: &str, to: u32) -> Option<Vec<u8>> {
        let ids = self.list_ids(name);
        let from = ids.iter().position(|i| i == id)?;
        let to = (to as usize).min(ids.len() - 1);
        let list = self.edit_list(name);
        let copies = {
            let txn = self.doc.transact();
            list.iter(&txn).filter(|v| out_text(v).as_deref() == Some(id)).count()
        };
        if from == to && copies == 1 {
            return None;
        }
        self.end_capture();
        let mut txn = self.doc.transact_mut_with(self.origin.clone());
        let raw = |txn: &yrs::TransactionMut| list.iter(txn).map(|v| out_text(&v).unwrap_or_default()).collect::<Vec<String>>();
        // Every copy after the first goes.
        let first = raw(&txn).iter().position(|v| v == id).unwrap_or(0);
        let extra: Vec<u32> = raw(&txn).iter().enumerate().filter(|(i, v)| *i != first && v.as_str() == id).map(|(i, _)| i as u32).collect();
        for i in extra.into_iter().rev() {
            list.remove(&mut txn, i);
        }
        if from != to {
            // The raw index of the `n`th id as read (the first copy of each),
            // or the end.
            let at = |raw: &[String], n: usize| -> u32 {
                let mut seen = HashSet::new();
                raw.iter().enumerate().filter(|(_, v)| seen.insert(v.as_str())).nth(n).map_or(raw.len() as u32, |(i, _)| i as u32)
            };
            let now = raw(&txn);
            let source = at(&now, from);
            // move_to places the item before what stands at the target now,
            // so a move down targets the slot after the destination.
            let target = at(&now, if to > from { to + 1 } else { to });
            list.move_to(&mut txn, source, target);
        }
        Some(txn.encode_update_v1())
    }

    /// The lists whose ids changed since the last call, sorted.
    pub fn lists_changed(&mut self) -> Vec<String> {
        let now: Vec<(String, String)> =
            self.list_names().into_iter().map(|name| (format!("{LIST}{name}"), self.list_ids(&name).join("\n"))).collect();
        self.changed_since(now, LIST)
    }

    fn list_ref(&self, name: &str) -> ArrayRef {
        self.doc.get_or_insert_array(format!("{LIST}{name}"))
    }

    fn edit_list(&mut self, name: &str) -> ArrayRef {
        let list = self.list_ref(name);
        self.scope(&format!("{LIST}{name}"), &list);
        list
    }

    /// The raw array index of the `index`th id as read (the first copy of
    /// each), or the array's end past the last.
    fn raw_index(&self, list: &ArrayRef, read: &[String], index: u32) -> u32 {
        let txn = self.doc.transact();
        let Some(want) = read.get(index as usize) else {
            return list.len(&txn);
        };
        list.iter(&txn).position(|v| out_text(&v).as_deref() == Some(want.as_str())).map_or(list.len(&txn), |i| i as u32)
    }

    /// The merged text of a paragraph.
    pub fn text(&self, para: &str) -> String {
        if let Some(slot) = self.slot(para) {
            return slot.text;
        }
        let text = self.doc.get_or_insert_text(para.to_string());
        let txn = self.doc.transact();
        text.get_string(&txn)
    }

    /// Applies the local change `before -> after` to `para` and returns the
    /// CRDT update to broadcast, `None` when nothing changed.
    ///
    /// This reconstructs the edit from the text, which is ambiguous when an
    /// insert's text shares context with what is already there; apps that
    /// know the exact edit (caret and typed text) should call
    /// [`TextMerge::local_edit_exact`] instead.
    pub fn local_edit(&mut self, para: &str, before: &str, after: &str) -> Option<Vec<u8>> {
        let (index, removed, inserted) = splice(before, after);
        self.local_edit_exact(para, index, removed.len() as u32, &inserted)
    }

    /// Applies an exact local edit: `remove_len` bytes at `index`, replaced
    /// by `insert`. Never panics on a stale position: it clamps into the
    /// paragraph. A paragraph the body does not hold is a paragraph of its
    /// own (outside the body).
    pub fn local_edit_exact(&mut self, para: &str, index: u32, remove_len: u32, insert: &str) -> Option<Vec<u8>> {
        if remove_len == 0 && insert.is_empty() {
            return None;
        }
        // Reset ends the previous capture window: one command is one undo step.
        self.end_capture();
        let (text, base, len) = match self.slot(para) {
            Some(slot) => (self.edit_text(slot.body.as_deref()), slot.start(), slot.text.len() as u32),
            None => {
                let text = self.outside_text(para);
                let len = text.get_string(&self.doc.transact()).len() as u32;
                (text, 0, len)
            }
        };
        let index = index.min(len);
        let remove_len = remove_len.min(len - index);
        if remove_len == 0 && insert.is_empty() {
            return None;
        }
        let mut txn = self.doc.transact_mut_with(self.origin.clone());
        if remove_len > 0 {
            text.remove_range(&mut txn, base + index, remove_len);
        }
        if !insert.is_empty() {
            // Typed text continues the formatting where it lands (bold
            // inside bold) but never the leader's paragraph attributes: yrs
            // carries the left neighbour's attributes into an insert unless
            // they are ended explicitly.
            text.insert_with_attributes(&mut txn, base + index, insert, plain_attrs());
        }
        Some(txn.encode_update_v1())
    }

    /// Makes the paragraph's CRDT text say `target`, returning the update
    /// when it differed (a repair after an exact edit landed differently,
    /// e.g. autocorrect changed the document).
    pub fn sync(&mut self, para: &str, target: &str) -> Option<Vec<u8>> {
        let current = self.text(para);
        if current == target {
            return None;
        }
        let (index, removed, inserted) = splice(&current, target);
        self.local_edit_exact(para, index, removed.len() as u32, &inserted)
    }

    /// Makes the paragraph's CRDT text say `target` with its inline objects
    /// `objects` (byte offset in `target`, payload), in one update: a peer
    /// never sees an object without its payload. Text and objects are
    /// compared together, an object equal only to one with the same payload,
    /// so the one contiguous change between them is removed and inserted and
    /// nothing outside it is touched: an object a peer deleted meanwhile
    /// stays deleted, and one inserted next to it is its own item. `None`
    /// when nothing changed.
    pub fn sync_objects(&mut self, para: &str, target: &str, objects: &[(u32, String)]) -> Option<Vec<u8>> {
        let current = self.text(para);
        let held = self.objects(para);
        let (a, b) = (tokens(&current, &held), tokens(target, objects));
        let mut pre = 0;
        while pre < a.len() && pre < b.len() && a[pre].1 == b[pre].1 && a[pre].2 == b[pre].2 {
            pre += 1;
        }
        let mut suf = 0;
        while suf < a.len() - pre
            && suf < b.len() - pre
            && a[a.len() - 1 - suf].1 == b[b.len() - 1 - suf].1
            && a[a.len() - 1 - suf].2 == b[b.len() - 1 - suf].2
        {
            suf += 1;
        }
        let byte = |t: &[(usize, char, Option<&str>)], i: usize, whole: &str| t.get(i).map_or(whole.len(), |x| x.0);
        let (from, to) = (byte(&a, pre, &current), byte(&a, a.len() - suf, &current));
        if from == to && pre == b.len() - suf {
            return None;
        }
        self.end_capture();
        let (text, base) = match self.slot(para) {
            Some(slot) => (self.edit_text(slot.body.as_deref()), slot.start()),
            None => (self.outside_text(para), 0),
        };
        let mut txn = self.doc.transact_mut_with(self.origin.clone());
        if to > from {
            text.remove_range(&mut txn, base + from as u32, (to - from) as u32);
        }
        // The inserted middle, in runs: plain text, and each object with its payload.
        let mut at = base + from as u32;
        let mut run = String::new();
        for &(_, c, payload) in &b[pre..b.len() - suf] {
            match payload {
                Some(p) => {
                    if !run.is_empty() {
                        text.insert_with_attributes(&mut txn, at, &run, plain_attrs());
                        at += run.len() as u32;
                        run.clear();
                    }
                    text.insert_with_attributes(&mut txn, at, &OBJECT_CHAR.to_string(), object_attrs(p));
                    at += OBJECT_CHAR.len_utf8() as u32;
                }
                None => run.push(c),
            }
        }
        if !run.is_empty() {
            text.insert_with_attributes(&mut txn, at, &run, plain_attrs());
        }
        Some(txn.encode_update_v1())
    }

    /// The paragraph's inline objects, in order: each [`OBJECT_CHAR`] with a
    /// payload, as (byte offset within the paragraph, payload). A bare
    /// [`OBJECT_CHAR`] (text from before objects travelled) is not one.
    pub fn objects(&self, para: &str) -> Vec<(u32, String)> {
        let outside = (!self.in_body(para) && self.slot(para).is_none()).then(|| self.doc.get_or_insert_text(para.to_string()));
        let slot = self.slot(para);
        let txn = self.doc.transact();
        let (chunks, range) = match (&outside, &slot) {
            (None, Some(slot)) => {
                (self.text_of(slot.body.as_deref()).diff(&txn, |_| ()), Some((slot.start(), slot.start() + slot.text.len() as u32)))
            }
            (Some(text), _) => (text.diff(&txn, |_| ()), None),
            (None, None) => return Vec::new(),
        };
        let (from, to) = range.unwrap_or((0, u32::MAX));
        let mut out = Vec::new();
        let mut pos = 0u32;
        for chunk in chunks {
            let Some(s) = out_text(&chunk.insert) else { continue };
            let payload = chunk.attributes.as_deref().and_then(|a| a.get(OBJ)).and_then(any_string);
            if let Some(payload) = payload {
                for (i, c) in s.char_indices() {
                    let at = pos + i as u32;
                    if c == OBJECT_CHAR && at >= from && at < to {
                        out.push((at - from, payload.clone()));
                    }
                }
            }
            pos += s.len() as u32;
        }
        out
    }

    /// Splits body paragraph `para` at byte `at`: everything after `at`
    /// becomes the new paragraph `new_para` (with `props`). One leader is
    /// inserted; no text moves, so concurrent typing anywhere survives and
    /// two concurrent splits make three paragraphs, never a duplicate.
    pub fn local_split(&mut self, para: &str, at: u32, new_para: &str, props: Option<&str>) -> Option<Vec<u8>> {
        let slot = self.slot(para)?;
        if self.in_body(new_para) {
            return None;
        }
        self.end_capture();
        let at = at.min(slot.text.len() as u32);
        let body = self.edit_text(slot.body.as_deref());
        let mut txn = self.doc.transact_mut_with(self.origin.clone());
        body.insert_with_attributes(&mut txn, slot.start() + at, LEADER, leader_attrs(new_para, props));
        Some(txn.encode_update_v1())
    }

    /// Joins body paragraph `para` onto the paragraph before it (Backspace
    /// at its start, Delete at the end of the one before): its leader goes,
    /// so its text — including anything typed into it concurrently — joins
    /// the previous paragraph. `None` for the first paragraph of its body or
    /// an unknown one.
    pub fn local_join(&mut self, para: &str) -> Option<Vec<u8>> {
        let slot = self.slot(para)?;
        let text = self.text_of(slot.body.as_deref());
        let first = slots_in(&text, slot.body.as_deref(), &self.doc.transact()).first().map(|s| s.para.clone());
        if first.as_deref() == Some(para) {
            return None;
        }
        self.end_capture();
        let body = self.edit_text(slot.body.as_deref());
        let mut txn = self.doc.transact_mut_with(self.origin.clone());
        body.remove_range(&mut txn, slot.leader_at, LEADER.len() as u32);
        Some(txn.encode_update_v1())
    }

    /// Every change this CRDT holds, from the beginning: what a joining peer
    /// needs to seed an empty CRDT to this state.
    pub fn full_update(&self) -> Vec<u8> {
        let txn = self.doc.transact();
        txn.encode_state_as_update_v1(&yrs::StateVector::default())
    }

    /// Applies a document-wide update (a seed, a sync or a peer's edit); the
    /// caller reconciles the paragraphs from [`TextMerge::body_paragraphs`].
    pub fn apply_doc_update(&mut self, update: &[u8]) -> Result<(), String> {
        let update = Update::decode_v1(update).map_err(|e| format!("{e:?}"))?;
        let mut txn = self.doc.transact_mut();
        txn.apply_update(update).map_err(|e| format!("{e:?}"))
    }

    /// Applies a peer's update while carrying local positions (`(para, byte
    /// offset)`, a caret's ends) across it: a position follows the text it
    /// stands after, so a remote insert before it moves it, a remote insert
    /// exactly at it lands after it, a remote split carries it into the new
    /// paragraph and a remote join carries it into the joined one. Positions
    /// outside the body come back unchanged.
    pub fn apply_update_carrying(&mut self, update: &[u8], positions: &[(String, u32)]) -> Result<Vec<(String, u32)>, String> {
        let update = Update::decode_v1(update).map_err(|e| format!("{e:?}"))?;
        // Each position's slot and the body text it lives in, resolved
        // before any transaction opens (naming a body takes one).
        let located: Vec<Option<(Slot, TextRef)>> = positions
            .iter()
            .map(|(para, _)| {
                self.slot(para).map(|slot| {
                    let text = self.text_of(slot.body.as_deref());
                    (slot, text)
                })
            })
            .collect();
        let stickies: Vec<Option<StickyIndex>> = {
            let mut txn = self.doc.transact_mut();
            positions
                .iter()
                .zip(&located)
                .map(|((_, off), found)| {
                    let (slot, text) = found.as_ref()?;
                    let at = slot.start() + (*off).min(slot.text.len() as u32);
                    // Before: the position belongs to the character before it
                    // (the leader, at a paragraph's start).
                    text.sticky_index(&mut txn, at, Assoc::Before)
                })
                .collect()
        };
        {
            let mut txn = self.doc.transact_mut();
            txn.apply_update(update).map_err(|e| format!("{e:?}"))?;
        }
        let txn = self.doc.transact();
        let mut slots_of: HashMap<Option<String>, Vec<Slot>> = HashMap::new();
        Ok(positions
            .iter()
            .zip(stickies)
            .zip(&located)
            .map(|(((para, off), sticky), found)| {
                let (Some(index), Some((slot, text))) = (sticky.and_then(|s| s.get_offset(&txn)).map(|o| o.index), found) else {
                    return (para.clone(), *off);
                };
                let slots = slots_of.entry(slot.body.clone()).or_insert_with(|| slots_in(text, slot.body.as_deref(), &txn));
                // The paragraph whose leader is at or before the index.
                match slots.iter().rev().find(|s| s.leader_at < index || (s.leader_at == index && index == 0)) {
                    Some(slot) => (slot.para.clone(), index.saturating_sub(slot.start()).min(slot.text.len() as u32)),
                    None => (para.clone(), *off),
                }
            })
            .collect())
    }

    /// Applies a bold change over `[index, index+len)` of a paragraph as a
    /// CRDT attribute: the formatting travels with the text items, so it
    /// covers exactly the characters the author covered, whatever concurrent
    /// inserts land. Returns the update to broadcast, `None` when nothing changed.
    pub fn local_bold(&mut self, para: &str, index: u32, len: u32, bold: bool) -> Option<Vec<u8>> {
        if len == 0 {
            return None;
        }
        self.end_capture();
        let (text, base, total) = match self.slot(para) {
            Some(slot) => (self.edit_text(slot.body.as_deref()), slot.start(), slot.text.len() as u32),
            None => {
                let text = self.outside_text(para);
                let len = text.get_string(&self.doc.transact()).len() as u32;
                (text, 0, len)
            }
        };
        let index = index.min(total);
        let len = len.min(total - index);
        if len == 0 {
            return None;
        }
        let value = if bold { Any::Bool(true) } else { Any::Null };
        let attrs: Attrs = [(Arc::<str>::from("bold"), value)].into_iter().collect();
        let mut txn = self.doc.transact_mut_with(self.origin.clone());
        text.format(&mut txn, base + index, len, attrs);
        Some(txn.encode_update_v1())
    }

    /// The bold spans (byte ranges within the paragraph) the CRDT holds for
    /// `para`, in order: the item-anchored truth every replica derives runs from.
    pub fn bold_spans(&self, para: &str) -> Vec<(u32, u32)> {
        let slot = self.slot(para);
        let text = match &slot {
            Some(slot) => self.text_of(slot.body.as_deref()),
            None => self.doc.get_or_insert_text(para.to_string()),
        };
        let txn = self.doc.transact();
        let chunks = text.diff(&txn, |_| ());
        let range = slot.map(|slot| (slot.start(), slot.start() + slot.text.len() as u32));
        let (from, to) = range.unwrap_or((0, u32::MAX));
        let mut spans = Vec::new();
        let mut pos = 0u32;
        for chunk in chunks {
            let Some(s) = out_text(&chunk.insert) else { continue };
            let n = s.len() as u32;
            let bold = chunk.attributes.as_deref().and_then(|a| a.get("bold")).is_some_and(|v| matches!(v, Any::Bool(true)));
            let (a, b) = (pos.max(from), (pos + n).min(to));
            if bold && a < b {
                spans.push((a - from, b - from));
            }
            pos += n;
        }
        // Adjacent spans (split only by a chunk boundary) are one span.
        let mut merged: Vec<(u32, u32)> = Vec::new();
        for (a, b) in spans {
            match merged.last_mut() {
                Some(last) if last.1 == a => last.1 = b,
                _ => merged.push((a, b)),
            }
        }
        merged
    }

    /// Undoes this author's most recent local edit (typing, a split, a join,
    /// a bold), whatever paragraph it touched: the update to broadcast.
    /// Nothing when the local author has no edit to undo; peers' edits are
    /// never undone.
    pub fn undo_local(&mut self) -> Option<Vec<u8>> {
        if !self.undo.can_undo() {
            return None;
        }
        let before = self.doc.transact().state_vector();
        if !self.undo.undo_blocking() {
            return None;
        }
        let txn = self.doc.transact();
        Some(txn.encode_state_as_update_v1(&before))
    }
}

/// Writes `paras` into an empty body, with no author.
fn seed_into(doc: &Doc, body: &TextRef, paras: &[BodyParagraph]) -> Vec<u8> {
    let mut txn = doc.transact_mut();
    let mut at = 0u32;
    for p in paras {
        body.insert_with_attributes(&mut txn, at, LEADER, leader_attrs(&p.para, p.props.as_deref()));
        at += LEADER.len() as u32;
        if !p.text.is_empty() {
            body.insert_with_attributes(&mut txn, at, &p.text, plain_attrs());
            at += p.text.len() as u32;
        }
    }
    txn.encode_update_v1()
}

/// The leader's attributes: the paragraph id, and its properties when given.
fn leader_attrs(para: &str, props: Option<&str>) -> Attrs {
    let mut attrs: HashMap<Arc<str>, Any> = HashMap::new();
    attrs.insert(Arc::from(PID), Any::String(Arc::from(para)));
    if let Some(props) = props {
        attrs.insert(Arc::from(PROPS), Any::String(Arc::from(props)));
    }
    attrs.into_iter().collect()
}

/// The paragraph attributes ended: what every non-leader insert carries.
fn plain_attrs() -> Attrs {
    [(Arc::<str>::from(PID), Any::Null), (Arc::<str>::from(PROPS), Any::Null), (Arc::<str>::from(OBJ), Any::Null)].into_iter().collect()
}

/// An inline object's attributes: plain, with its payload.
fn object_attrs(payload: &str) -> Attrs {
    let mut attrs = plain_attrs();
    attrs.insert(Arc::<str>::from(OBJ), Any::String(Arc::from(payload)));
    attrs
}

/// A paragraph's text as tokens for [`TextMerge::sync_objects`]: each char,
/// with its payload when it is an object (a bare [`OBJECT_CHAR`] has none).
fn tokens<'a>(text: &'a str, objects: &'a [(u32, String)]) -> Vec<(usize, char, Option<&'a str>)> {
    text.char_indices()
        .map(|(i, c)| (i, c, (c == OBJECT_CHAR).then(|| objects.iter().find(|(at, _)| *at as usize == i).map(|(_, p)| p.as_str())).flatten()))
        .collect()
}

fn any_string(v: &Any) -> Option<String> {
    match v {
        Any::String(s) => Some(s.to_string()),
        _ => None,
    }
}

/// The single contiguous change from `before` to `after`: the byte index,
/// the removed text and the inserted text. Byte offsets, like the apps'.
pub(crate) fn splice(before: &str, after: &str) -> (u32, String, String) {
    let max = before.len().min(after.len());
    let mut pre = 0;
    while pre < max && before.as_bytes()[pre] == after.as_bytes()[pre] {
        pre += 1;
    }
    while pre > 0 && !(before.is_char_boundary(pre) && after.is_char_boundary(pre)) {
        pre -= 1;
    }
    let mut suf = 0;
    while suf < max - pre && before.as_bytes()[before.len() - 1 - suf] == after.as_bytes()[after.len() - 1 - suf] {
        suf += 1;
    }
    while suf > 0 && !(before.is_char_boundary(before.len() - suf) && after.is_char_boundary(after.len() - suf)) {
        suf -= 1;
    }
    (pre as u32, before[pre..before.len() - suf].to_string(), after[pre..after.len() - suf].to_string())
}

/// The text of a diff chunk, when it is text.
fn out_text(out: &Out) -> Option<String> {
    match out {
        Out::Any(Any::String(s)) => Some(s.to_string()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn para(id: &str, text: &str) -> BodyParagraph {
        BodyParagraph { para: id.into(), text: text.into(), props: None }
    }

    /// Two authors sharing a seeded body: A seeds, B applies the seed.
    fn pair(paras: &[BodyParagraph]) -> (TextMerge, TextMerge) {
        let mut a = TextMerge::new("a");
        let mut b = TextMerge::new("b");
        let seed = a.seed_body(paras).expect("seed");
        b.apply_doc_update(&seed).expect("B seeds");
        (a, b)
    }

    fn exchange(a: &mut TextMerge, b: &mut TextMerge, ua: &[u8], ub: &[u8]) {
        a.apply_doc_update(ub).expect("A applies");
        b.apply_doc_update(ua).expect("B applies");
    }

    fn texts(m: &TextMerge) -> Vec<(String, String)> {
        m.body_paragraphs().into_iter().map(|p| (p.para, p.text)).collect()
    }

    #[test]
    fn two_editors_converge() {
        let (mut a, mut b) = pair(&[para("p1", "")]);
        // A and B type into the same empty paragraph, before hearing from each other.
        let ua = a.local_edit("p1", "", "Hello ").expect("A's edit is an update");
        let ub = b.local_edit("p1", "", "world").expect("B's edit is an update");
        exchange(&mut a, &mut b, &ua, &ub);
        let ta = a.text("p1");
        assert_eq!(ta, b.text("p1"), "both sides converge to the same text");
        assert!(ta.contains("Hello ") && ta.contains("world"), "neither edit was lost: {ta:?}");

        // Interleaved edits at both ends converge too.
        let ua2 = a.local_edit("p1", &ta, &format!("{ta}!")).expect("A appends");
        let ub2 = b.local_edit("p1", &ta, &format!("?{ta}")).expect("B prepends");
        exchange(&mut a, &mut b, &ua2, &ub2);
        assert_eq!(a.text("p1"), b.text("p1"), "interleaved edits converge");
    }

    #[test]
    fn the_seeded_body_reads_back_paragraph_by_paragraph() {
        let (a, b) = pair(&[
            BodyParagraph { para: "1".into(), text: "Title".into(), props: Some("{\"style\":\"Heading1\"}".into()) },
            para("2", "First line\\nwith a typed break"),
            para("3", ""),
        ]);
        for m in [&a, &b] {
            let ps = m.body_paragraphs();
            assert_eq!(ps.len(), 3);
            assert_eq!(ps[0].props.as_deref(), Some("{\"style\":\"Heading1\"}"));
            assert_eq!(ps[1].text, "First line\\nwith a typed break");
            assert_eq!(ps[2].text, "");
        }
    }

    #[test]
    fn a_typed_line_break_stays_inside_its_paragraph() {
        let (mut a, b) = pair(&[para("1", "ab"), para("2", "cd")]);
        let u = a.local_edit_exact("1", 1, 0, "\n").expect("a line break");
        let mut b = b;
        b.apply_doc_update(&u).expect("B applies");
        assert_eq!(texts(&b), vec![("1".to_string(), "a\nb".to_string()), ("2".to_string(), "cd".to_string())], "no new paragraph");
    }

    #[test]
    fn a_split_travels_and_text_typed_into_the_new_paragraph_follows_it() {
        let (mut a, mut b) = pair(&[para("1", "Field notes. Hana writes.")]);
        let u = a.local_split("1", 13, "9", None).expect("Enter");
        b.apply_doc_update(&u).expect("B applies the split");
        assert_eq!(texts(&b), vec![("1".to_string(), "Field notes. ".to_string()), ("9".to_string(), "Hana writes.".to_string())]);
        let u = a.local_edit_exact("9", 12, 0, " More.").expect("typing in the new paragraph");
        b.apply_doc_update(&u).expect("B applies");
        assert_eq!(b.text("9"), "Hana writes. More.");
        assert_eq!(texts(&a), texts(&b));
    }

    #[test]
    fn two_concurrent_enters_in_one_paragraph_make_three_paragraphs_and_no_duplicate() {
        let (mut a, mut b) = pair(&[para("1", "aaaa bbbb cccc")]);
        let ua = a.local_split("1", 5, "10", None).expect("A presses Enter");
        let ub = b.local_split("1", 10, "20", None).expect("B presses Enter");
        exchange(&mut a, &mut b, &ua, &ub);
        assert_eq!(texts(&a), texts(&b), "converged");
        let joined: String = texts(&a).into_iter().map(|(_, t)| t).collect();
        assert_eq!(joined, "aaaa bbbb cccc", "no text duplicated or lost: {:?}", texts(&a));
        assert_eq!(texts(&a).len(), 3);
    }

    #[test]
    fn two_concurrent_enters_at_the_same_spot_make_an_empty_paragraph_not_a_duplicate() {
        let (mut a, mut b) = pair(&[para("1", "left right")]);
        let ua = a.local_split("1", 5, "10", None).expect("A");
        let ub = b.local_split("1", 5, "20", None).expect("B");
        exchange(&mut a, &mut b, &ua, &ub);
        assert_eq!(texts(&a), texts(&b));
        let joined: String = texts(&a).into_iter().map(|(_, t)| t).collect();
        assert_eq!(joined, "left right");
        assert_eq!(texts(&a).len(), 3, "{:?}", texts(&a));
    }

    #[test]
    fn a_join_keeps_text_typed_concurrently_into_the_joined_paragraph() {
        let (mut a, mut b) = pair(&[para("1", "one"), para("2", "two")]);
        // A joins 2 onto 1 (Backspace at its start) while B types into 2.
        let ua = a.local_join("2").expect("A joins");
        let ub = b.local_edit_exact("2", 3, 0, " and three").expect("B types into 2");
        exchange(&mut a, &mut b, &ua, &ub);
        assert_eq!(texts(&a), texts(&b));
        assert_eq!(texts(&a), vec![("1".to_string(), "onetwo and three".to_string())], "B's typing survived the join");
    }

    #[test]
    fn the_first_paragraph_cannot_be_joined_away() {
        let (mut a, _) = pair(&[para("1", "one"), para("2", "two")]);
        assert!(a.local_join("1").is_none());
    }

    #[test]
    fn a_caret_is_carried_across_a_remote_split_join_and_insert() {
        let (mut a, mut b) = pair(&[para("1", "Field notes. Hana writes."), para("2", "Ines")]);
        // B's caret at the end of paragraph 1; A splits it before "Hana".
        let u = a.local_split("1", 13, "9", None).expect("split");
        let carried = b.apply_update_carrying(&u, &[("1".into(), 25), ("1".into(), 5)]).expect("apply");
        assert_eq!(carried, vec![("9".to_string(), 12), ("1".to_string(), 5)], "after the split: into the new paragraph; before it: unmoved");
        // A inserts at the start of paragraph 2 while B's caret is at its end.
        let u = a.local_edit_exact("2", 0, 0, "Dear ").expect("insert");
        let carried = b.apply_update_carrying(&u, &[("2".into(), 4)]).expect("apply");
        assert_eq!(carried, vec![("2".to_string(), 9)], "a remote insert before the caret moves it");
        // A inserts exactly at B's caret: the remote text lands after it.
        let u = a.local_edit_exact("2", 9, 0, "!").expect("insert at the caret");
        let carried = b.apply_update_carrying(&u, &[("2".into(), 9)]).expect("apply");
        assert_eq!(carried, vec![("2".to_string(), 9)]);
        // A joins 2 onto 9; B's caret in 2 travels into 9.
        let u = a.local_join("2").expect("join");
        let carried = b.apply_update_carrying(&u, &[("2".into(), 2)]).expect("apply");
        assert_eq!(carried, vec![("9".to_string(), 12 + 2)], "into the joined paragraph, after its old text");
        assert_eq!(texts(&a), texts(&b));
    }

    #[test]
    fn bold_is_anchored_to_the_text_it_covers() {
        let (mut a, mut b) = pair(&[para("p1", "")]);
        let u = a.local_edit_exact("p1", 0, 0, "Bravo. Alpha. ").expect("text");
        b.apply_doc_update(&u).expect("B applies");
        // B bolds "Alpha." (bytes 7..13); A inserts "ONE " inside it meanwhile.
        let ub = b.local_bold("p1", 7, 6, true).expect("bold");
        let ua = a.local_edit_exact("p1", 10, 0, "ONE ").expect("insert");
        exchange(&mut a, &mut b, &ua, &ub);
        assert_eq!(a.text("p1"), b.text("p1"), "text converged");
        assert_eq!(a.bold_spans("p1"), b.bold_spans("p1"), "the bold covers the same characters on both: item-anchored");
        assert!(!a.bold_spans("p1").is_empty(), "and it is still there");
    }

    #[test]
    fn bold_spans_are_relative_to_their_paragraph() {
        let (mut a, _) = pair(&[para("1", "aaaa"), para("2", "bbbb cccc")]);
        a.local_bold("2", 5, 4, true).expect("bold");
        assert_eq!(a.bold_spans("2"), vec![(5, 9)]);
        assert!(a.bold_spans("1").is_empty());
    }

    #[test]
    fn undo_is_per_author() {
        let (mut a, mut b) = pair(&[para("p1", "")]);
        let ua = a.local_edit("p1", "", "Hello ").expect("A's edit");
        let ub = b.local_edit("p1", "", "world").expect("B's edit");
        exchange(&mut a, &mut b, &ua, &ub);
        let update = a.undo_local().expect("A has something to undo");
        assert_eq!(a.text("p1"), "world", "only A's own edit was undone");
        b.apply_doc_update(&update).expect("B applies the undo");
        assert_eq!(b.text("p1"), "world");
    }

    #[test]
    fn undo_survives_interleaved_edits() {
        let (mut a, mut b) = pair(&[para("p1", "")]);
        let ua = a.local_edit_exact("p1", 0, 0, "Hello from Alice. ").expect("A's edit");
        b.apply_doc_update(&ua).expect("B applies A");
        let ub = b.local_edit_exact("p1", 0, 0, "Hi from Bob. ").expect("B's edit");
        a.apply_doc_update(&ub).expect("A applies B");
        let update = a.undo_local().expect("A undoes");
        b.apply_doc_update(&update).expect("B applies A's undo");
        assert_eq!(b.text("p1"), "Hi from Bob. ", "A's undo left only B's text");
        let update = b.undo_local().expect("B undoes");
        a.apply_doc_update(&update).expect("A applies B's undo");
        assert_eq!(a.text("p1"), "");
    }

    #[test]
    fn undo_takes_back_the_latest_edit_first_across_paragraphs_and_rejoins_a_split() {
        let (mut a, mut b) = pair(&[para("1", "one"), para("2", "two")]);
        let u1 = a.local_edit_exact("2", 3, 0, "!").expect("typing in 2");
        let u2 = a.local_split("1", 1, "9", None).expect("Enter in 1");
        b.apply_doc_update(&u1).expect("B");
        b.apply_doc_update(&u2).expect("B");
        let undo = a.undo_local().expect("undo the split");
        assert_eq!(texts(&a), vec![("1".to_string(), "one".to_string()), ("2".to_string(), "two!".to_string())], "the split went first");
        b.apply_doc_update(&undo).expect("B applies");
        assert_eq!(texts(&a), texts(&b));
        let undo = a.undo_local().expect("then the typing");
        b.apply_doc_update(&undo).expect("B applies");
        assert_eq!(b.text("2"), "two");
    }

    #[test]
    fn a_paragraph_outside_the_body_keeps_a_text_of_its_own() {
        let (mut a, mut b) = pair(&[para("1", "body")]);
        let u = a.local_edit_exact("cell-7", 0, 0, "in a table").expect("outside edit");
        b.apply_doc_update(&u).expect("B applies");
        assert_eq!(b.text("cell-7"), "in a table");
        assert!(!b.in_body("cell-7"));
        assert_eq!(texts(&b), vec![("1".to_string(), "body".to_string())]);
        let undo = a.undo_local().expect("its undo is covered too");
        b.apply_doc_update(&undo).expect("B applies");
        assert_eq!(b.text("cell-7"), "");
    }

    #[test]
    fn concurrent_writes_to_one_key_keep_the_same_value_everywhere() {
        let (mut a, mut b) = pair(&[para("1", "x")]);
        let ua = a.register_set("s1!B2", "=1+1").expect("A writes");
        let ub = b.register_set("s1!B2", "42").expect("B writes");
        exchange(&mut a, &mut b, &ua, &ub);
        assert_eq!(a.register_get("s1!B2"), b.register_get("s1!B2"), "one winner, the same on both");
        assert_eq!(a.register_entries(), b.register_entries());
        assert_eq!(texts(&a), vec![("1".into(), "x".into())], "the body is untouched");
    }

    #[test]
    fn a_peers_write_reports_its_key_and_an_unchanged_write_sends_nothing() {
        let (mut a, mut b) = pair(&[para("1", "x")]);
        a.register_changed();
        let u = b.register_set("k", "v").expect("B writes");
        assert!(b.register_set("k", "v").is_none(), "the same value again is no update");
        a.apply_doc_update(&u).expect("A applies");
        assert_eq!(a.register_changed(), vec!["k".to_string()]);
        assert!(a.register_changed().is_empty(), "drained");
        let gone = b.register_remove("k").expect("B removes");
        assert!(b.register_remove("k").is_none(), "nothing left to remove");
        a.apply_doc_update(&gone).expect("A applies");
        assert_eq!(a.register_changed(), vec!["k".to_string()]);
        assert_eq!(a.register_get("k"), None);
    }

    #[test]
    fn undo_takes_back_only_this_authors_register_write() {
        let (mut a, mut b) = pair(&[para("1", "x")]);
        let ua = a.register_set("A1", "mine").expect("A");
        b.apply_doc_update(&ua).expect("B gets A's");
        std::thread::sleep(std::time::Duration::from_millis(600)); // a new undo step
        let ub = b.register_set("B1", "theirs").expect("B");
        a.apply_doc_update(&ub).expect("A gets B's");
        a.register_changed();
        let undone = a.undo_local().expect("A undoes");
        assert_eq!(a.register_changed(), vec!["A1".to_string()], "the undo reports its key");
        b.apply_doc_update(&undone).expect("B gets the undo");
        for m in [&a, &b] {
            assert_eq!(m.register_get("A1"), None, "A's write is undone");
            assert_eq!(m.register_get("B1").as_deref(), Some("theirs"), "B's stays");
        }
    }

    #[test]
    fn undo_after_a_seed_returns_to_the_seeded_value_not_to_nothing() {
        let mut a = TextMerge::new("a");
        a.register_seed(&[("c/1/A1".into(), "seeded".into())]).expect("seed");
        assert!(a.undo_local().is_none(), "the seed is nobody's edit");
        a.register_set("c/1/A1", "edited").expect("edit");
        a.undo_local().expect("undo the edit");
        assert_eq!(a.register_get("c/1/A1").as_deref(), Some("seeded"));
        assert!(a.register_seed(&[]).is_none());
    }

    #[test]
    fn a_snapshot_carries_the_register_to_a_joiner() {
        let mut a = TextMerge::new("a");
        a.register_set("sheet/1", "Sheet1").expect("write");
        let mut joiner = TextMerge::new("j");
        joiner.apply_doc_update(&a.full_update()).expect("seed");
        assert_eq!(joiner.register_entries(), vec![("sheet/1".to_string(), "Sheet1".to_string())]);
        assert_eq!(joiner.register_changed(), vec!["sheet/1".to_string()], "the joiner learns which keys to read");
    }
}

/// Named bodies and ordered lists: the 0.2 Enter/join races run against a
/// named body, and the list's concurrent inserts, moves and removes.
#[cfg(test)]
mod named_tests {
    use super::*;

    const FRAME: &str = "4294967297";

    fn para(id: &str, text: &str) -> BodyParagraph {
        BodyParagraph { para: id.into(), text: text.into(), props: None }
    }

    /// Two authors sharing a named body: A seeds it, B applies the seed.
    fn pair(paras: &[BodyParagraph]) -> (TextMerge, TextMerge) {
        let mut a = TextMerge::new("a");
        let mut b = TextMerge::new("b");
        let seed = a.seed_named_body(FRAME, paras).expect("seed");
        b.apply_doc_update(&seed).expect("B seeds");
        (a, b)
    }

    fn exchange(a: &mut TextMerge, b: &mut TextMerge, ua: &[u8], ub: &[u8]) {
        a.apply_doc_update(ub).expect("A applies");
        b.apply_doc_update(ua).expect("B applies");
    }

    fn texts(m: &TextMerge) -> Vec<(String, String)> {
        m.named_body_paragraphs(FRAME).into_iter().map(|p| (p.para, p.text)).collect()
    }

    fn ids(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn a_named_body_reads_back_and_is_listed() {
        let (a, b) = pair(&[para("1", "Title"), para("2", "Point")]);
        assert_eq!(texts(&b), vec![("1".to_string(), "Title".to_string()), ("2".to_string(), "Point".to_string())]);
        assert_eq!(b.body_names(), vec![FRAME.to_string()]);
        assert!(a.body_paragraphs().is_empty(), "the unnamed body is untouched");
        assert!(b.in_body("2"));
    }

    #[test]
    fn a_split_in_a_named_body_travels_and_typing_follows_it() {
        let (mut a, mut b) = pair(&[para("1", "Field notes. Hana writes.")]);
        let u = a.local_split("1", 13, "9", None).expect("Enter");
        b.apply_doc_update(&u).expect("B applies the split");
        assert_eq!(texts(&b), vec![("1".to_string(), "Field notes. ".to_string()), ("9".to_string(), "Hana writes.".to_string())]);
        let u = a.local_edit_exact("9", 12, 0, " More.").expect("typing in the new paragraph");
        b.apply_doc_update(&u).expect("B applies");
        assert_eq!(b.text("9"), "Hana writes. More.");
        assert_eq!(texts(&a), texts(&b));
    }

    #[test]
    fn two_concurrent_enters_in_a_named_body_make_three_paragraphs_and_no_duplicate() {
        let (mut a, mut b) = pair(&[para("1", "aaaa bbbb cccc")]);
        let ua = a.local_split("1", 5, "10", None).expect("A presses Enter");
        let ub = b.local_split("1", 10, "20", None).expect("B presses Enter");
        exchange(&mut a, &mut b, &ua, &ub);
        assert_eq!(texts(&a), texts(&b));
        assert_eq!(texts(&a).into_iter().map(|(_, t)| t).collect::<String>(), "aaaa bbbb cccc");
        assert_eq!(texts(&a).len(), 3);
    }

    #[test]
    fn two_concurrent_enters_at_one_spot_in_a_named_body_make_an_empty_paragraph() {
        let (mut a, mut b) = pair(&[para("1", "left right")]);
        let ua = a.local_split("1", 5, "10", None).expect("A");
        let ub = b.local_split("1", 5, "20", None).expect("B");
        exchange(&mut a, &mut b, &ua, &ub);
        assert_eq!(texts(&a), texts(&b));
        assert_eq!(texts(&a).into_iter().map(|(_, t)| t).collect::<String>(), "left right");
        assert_eq!(texts(&a).len(), 3);
    }

    #[test]
    fn a_join_in_a_named_body_keeps_text_typed_concurrently() {
        let (mut a, mut b) = pair(&[para("1", "one"), para("2", "two")]);
        let ua = a.local_join("2").expect("A joins");
        let ub = b.local_edit_exact("2", 3, 0, " and three").expect("B types into 2");
        exchange(&mut a, &mut b, &ua, &ub);
        assert_eq!(texts(&a), texts(&b));
        assert_eq!(texts(&a), vec![("1".to_string(), "onetwo and three".to_string())]);
    }

    #[test]
    fn the_first_paragraph_of_a_named_body_cannot_be_joined_away() {
        let (mut a, _) = pair(&[para("1", "one"), para("2", "two")]);
        assert!(a.local_join("1").is_none());
    }

    #[test]
    fn a_caret_in_a_named_body_is_carried_across_a_remote_split_and_join() {
        let (mut a, mut b) = pair(&[para("1", "Field notes. Hana writes."), para("2", "Ines")]);
        let u = a.local_split("1", 13, "9", None).expect("split");
        let carried = b.apply_update_carrying(&u, &[("1".into(), 25), ("1".into(), 5)]).expect("apply");
        assert_eq!(carried, vec![("9".to_string(), 12), ("1".to_string(), 5)]);
        let u = a.local_join("2").expect("join");
        let carried = b.apply_update_carrying(&u, &[("2".into(), 2)]).expect("apply");
        assert_eq!(carried, vec![("9".to_string(), 12 + 2)]);
        assert_eq!(texts(&a), texts(&b));
    }

    #[test]
    fn bold_in_a_named_body_is_anchored_to_its_text() {
        let (mut a, mut b) = pair(&[para("p1", "Bravo. Alpha. ")]);
        let ub = b.local_bold("p1", 7, 6, true).expect("bold");
        let ua = a.local_edit_exact("p1", 10, 0, "ONE ").expect("insert");
        exchange(&mut a, &mut b, &ua, &ub);
        assert_eq!(a.text("p1"), b.text("p1"));
        assert_eq!(a.bold_spans("p1"), b.bold_spans("p1"));
        assert!(!a.bold_spans("p1").is_empty());
    }

    #[test]
    fn undo_in_a_named_body_is_per_author_and_latest_first() {
        let (mut a, mut b) = pair(&[para("1", "one"), para("2", "two")]);
        let u1 = a.local_edit_exact("2", 3, 0, "!").expect("typing in 2");
        let u2 = a.local_split("1", 1, "9", None).expect("Enter in 1");
        let ub = b.local_edit_exact("1", 0, 0, ">").expect("B types");
        exchange(&mut a, &mut b, &u1, &ub);
        b.apply_doc_update(&u2).expect("B");
        let undo = a.undo_local().expect("undo the split");
        b.apply_doc_update(&undo).expect("B applies");
        assert_eq!(texts(&a), vec![(String::from("1"), String::from(">one")), (String::from("2"), String::from("two!"))]);
        let undo = a.undo_local().expect("then the typing");
        b.apply_doc_update(&undo).expect("B applies");
        assert_eq!(texts(&b), vec![(String::from("1"), String::from(">one")), (String::from("2"), String::from("two"))], "B's typing stays");
        assert_eq!(texts(&a), texts(&b));
    }

    #[test]
    fn undo_never_takes_back_a_peers_edit_in_a_body_the_peer_made() {
        let mut a = TextMerge::new("a");
        let mut b = TextMerge::new("b");
        let seed = b.seed_named_body("peer", &[para("7", "")]).expect("B makes a frame");
        let typed = b.local_edit_exact("7", 0, 0, "B wrote this").expect("B types");
        a.apply_doc_update(&seed).expect("A");
        a.apply_doc_update(&typed).expect("A");
        assert!(a.undo_local().is_none(), "A has nothing of its own to undo");
        let mine = a.seed_named_body(FRAME, &[para("1", "")]).expect("A's frame");
        let ua = a.local_edit_exact("1", 0, 0, "A wrote this").expect("A types");
        b.apply_doc_update(&mine).expect("B");
        b.apply_doc_update(&ua).expect("B");
        let undo = a.undo_local().expect("A undoes its own typing");
        b.apply_doc_update(&undo).expect("B");
        assert_eq!(a.text("7"), "B wrote this");
        assert_eq!(b.text("7"), "B wrote this");
        assert_eq!(b.text("1"), "");
        assert!(a.undo_local().is_none(), "the seed is no one's to undo");
    }

    #[test]
    fn a_cleared_body_reads_empty_even_when_a_peer_typed_meanwhile() {
        let (mut a, mut b) = pair(&[para("1", "gone")]);
        let ua = a.clear_named_body(FRAME).expect("A deletes the frame");
        let ub = b.local_edit_exact("1", 4, 0, " but kept").expect("B still typing");
        exchange(&mut a, &mut b, &ua, &ub);
        assert_eq!(texts(&a), texts(&b));
        assert!(texts(&a).is_empty(), "the typing has no paragraph left to read in: {:?}", texts(&a));
        let raw = |m: &TextMerge| {
            let t = m.named_ref(FRAME);
            let txn = m.doc.transact();
            t.get_string(&txn)
        };
        assert_eq!(raw(&a), " but kept", "but the CRDT keeps it, the same on both");
        assert_eq!(raw(&a), raw(&b));
        let undo = a.undo_local().expect("A undoes the clear");
        b.apply_doc_update(&undo).expect("B");
        assert_eq!(texts(&a), vec![("1".to_string(), "gone but kept".to_string())], "the undo brings the paragraph back around B's typing");
        assert_eq!(texts(&a), texts(&b));
        assert_eq!(a.body_names(), vec![FRAME.to_string()], "the body is still named: whether the frame exists is the app's");
    }

    #[test]
    fn bodies_changed_reports_each_body_once_per_change() {
        let (mut a, mut b) = pair(&[para("1", "x")]);
        assert_eq!(b.bodies_changed(), vec![FRAME.to_string()]);
        assert!(b.bodies_changed().is_empty());
        let u = a.local_edit_exact("1", 1, 0, "y").expect("edit");
        b.apply_doc_update(&u).expect("B");
        assert_eq!(b.bodies_changed(), vec![FRAME.to_string()]);
    }

    #[test]
    fn bodies_are_independent() {
        let (mut a, mut b) = pair(&[para("1", "frame one")]);
        let u = a.seed_named_body("other", &[para("2", "frame two")]).expect("seed");
        b.apply_doc_update(&u).expect("B");
        let u = b.local_edit_exact("2", 0, 0, ">").expect("B types in two");
        a.apply_doc_update(&u).expect("A");
        assert_eq!(a.text("1"), "frame one");
        assert_eq!(a.text("2"), ">frame two");
        assert_eq!(a.body_names(), vec![FRAME.to_string(), "other".to_string()]);
    }

    fn list_pair(seed: &[&str]) -> (TextMerge, TextMerge) {
        let mut a = TextMerge::new("a");
        let mut b = TextMerge::new("b");
        let u = a.list_seed("slides", &ids(seed)).expect("seed");
        b.apply_doc_update(&u).expect("B");
        (a, b)
    }

    #[test]
    fn a_list_reads_back_inserts_and_removes() {
        let (mut a, mut b) = list_pair(&["s1", "s2", "s3"]);
        assert_eq!(b.list_ids("slides"), ids(&["s1", "s2", "s3"]));
        let u = a.list_insert("slides", 1, "s9").expect("insert");
        b.apply_doc_update(&u).expect("B");
        assert_eq!(b.list_ids("slides"), ids(&["s1", "s9", "s2", "s3"]));
        assert!(a.list_insert("slides", 0, "s9").is_none(), "already listed");
        let u = b.list_remove("slides", "s2").expect("remove");
        a.apply_doc_update(&u).expect("A");
        assert_eq!(a.list_ids("slides"), ids(&["s1", "s9", "s3"]));
        assert_eq!(a.list_names(), vec!["slides".to_string()]);
    }

    #[test]
    fn a_move_lands_where_it_says_up_and_down() {
        let (mut a, _) = list_pair(&["s1", "s2", "s3", "s4"]);
        a.list_move("slides", "s1", 2).expect("down");
        assert_eq!(a.list_ids("slides"), ids(&["s2", "s3", "s1", "s4"]));
        a.list_move("slides", "s4", 0).expect("up");
        assert_eq!(a.list_ids("slides"), ids(&["s4", "s2", "s3", "s1"]));
        a.list_move("slides", "s2", 9).expect("clamped to the end");
        assert_eq!(a.list_ids("slides"), ids(&["s4", "s3", "s1", "s2"]));
        assert!(a.list_move("slides", "s2", 3).is_none(), "already there");
    }

    #[test]
    fn two_concurrent_moves_of_one_id_converge_with_it_once_in_either_order() {
        for a_first in [true, false] {
            let (mut a, mut b) = list_pair(&["s1", "s2", "s3", "s4"]);
            let ua = a.list_move("slides", "s1", 3).expect("A moves s1 to the end");
            let ub = b.list_move("slides", "s1", 1).expect("B moves s1 to second");
            if a_first {
                exchange(&mut a, &mut b, &ua, &ub);
            } else {
                b.apply_doc_update(&ua).expect("B");
                a.apply_doc_update(&ub).expect("A");
            }
            let read = a.list_ids("slides");
            assert_eq!(read, b.list_ids("slides"), "converged");
            assert_eq!(read.iter().filter(|i| *i == "s1").count(), 1, "{read:?}");
            assert_eq!(read.len(), 4);
            let raw = {
                let l = a.list_ref("slides");
                let t = a.doc.transact();
                l.len(&t)
            };
            assert_eq!(raw, 4, "no copy in the CRDT either");
        }
    }

    #[test]
    fn a_move_against_a_remove_converges_with_the_id_gone() {
        for a_first in [true, false] {
            let (mut a, mut b) = list_pair(&["s1", "s2", "s3"]);
            let ua = a.list_move("slides", "s1", 2).expect("A moves s1");
            let ub = b.list_remove("slides", "s1").expect("B removes s1");
            if a_first {
                exchange(&mut a, &mut b, &ua, &ub);
            } else {
                b.apply_doc_update(&ua).expect("B");
                a.apply_doc_update(&ub).expect("A");
            }
            assert_eq!(a.list_ids("slides"), b.list_ids("slides"));
            assert_eq!(a.list_ids("slides"), ids(&["s2", "s3"]), "the removed id stays removed");
        }
    }

    #[test]
    fn two_authors_inserting_one_id_read_it_once_in_the_same_place() {
        let (mut a, mut b) = list_pair(&["s1", "s2"]);
        let ua = a.list_insert("slides", 0, "s9").expect("A inserts s9 first");
        let ub = b.list_insert("slides", 2, "s9").expect("B inserts s9 last");
        exchange(&mut a, &mut b, &ua, &ub);
        let read = a.list_ids("slides");
        assert_eq!(read, b.list_ids("slides"));
        assert_eq!(read.iter().filter(|i| *i == "s9").count(), 1, "{read:?}");
        let u = b.list_remove("slides", "s9").expect("removing removes every copy");
        a.apply_doc_update(&u).expect("A");
        assert_eq!(a.list_ids("slides"), ids(&["s1", "s2"]));
    }

    #[test]
    fn a_move_after_two_concurrent_inserts_moves_what_every_replica_reads() {
        let (mut a, mut b) = list_pair(&["a", "b"]);
        let ua = a.list_insert("slides", 0, "x").expect("A inserts x first");
        let ub = b.list_insert("slides", 1, "x").expect("B inserts x second");
        exchange(&mut a, &mut b, &ua, &ub);
        assert_eq!(a.list_ids("slides"), b.list_ids("slides"));
        let u = a.list_move("slides", "x", 2).expect("A moves x to the end");
        b.apply_doc_update(&u).expect("B");
        assert_eq!(a.list_ids("slides"), ids(&["a", "b", "x"]));
        assert_eq!(b.list_ids("slides"), ids(&["a", "b", "x"]));
        let raw = {
            let l = b.list_ref("slides");
            let t = b.doc.transact();
            l.len(&t)
        };
        assert_eq!(raw, 3, "the other copy went with the move");
    }

    #[test]
    fn a_move_in_place_still_drops_a_duplicate() {
        let (mut a, mut b) = list_pair(&["a"]);
        let ua = a.list_insert("slides", 1, "x").expect("A");
        let ub = b.list_insert("slides", 0, "x").expect("B");
        exchange(&mut a, &mut b, &ua, &ub);
        let at = a.list_ids("slides").iter().position(|i| i == "x").expect("listed") as u32;
        let u = a.list_move("slides", "x", at).expect("an in-place move cleans up the copy");
        b.apply_doc_update(&u).expect("B");
        assert_eq!(a.list_ids("slides"), b.list_ids("slides"));
        let raw = {
            let l = b.list_ref("slides");
            let t = b.doc.transact();
            l.len(&t)
        };
        assert_eq!(raw, 2);
    }

    #[test]
    fn a_step_undoes_as_one_whatever_it_touched() {
        let (mut a, mut b) = list_pair(&["s1"]);
        a.begin_step();
        let mut updates = vec![a.register_set("h/9", "{}").expect("record")];
        updates.extend(a.seed_named_body("9", &[para("1", "")]));
        updates.push(a.local_edit_exact("1", 0, 0, "new frame").expect("text"));
        updates.push(a.list_insert("slides", 1, "s2").expect("list"));
        a.end_step();
        for u in &updates {
            b.apply_doc_update(u).expect("B");
        }
        let later = a.local_edit_exact("1", 9, 0, "!").expect("a later edit");
        b.apply_doc_update(&later).expect("B");
        let undo = a.undo_local().expect("undo the later edit");
        b.apply_doc_update(&undo).expect("B");
        assert_eq!(b.text("1"), "new frame");
        let undo = a.undo_local().expect("one undo for the whole step");
        b.apply_doc_update(&undo).expect("B");
        assert_eq!(b.register_get("h/9"), None);
        assert_eq!(b.text("1"), "");
        assert_eq!(b.list_ids("slides"), ids(&["s1"]));
        assert!(a.undo_local().is_none());
    }

    #[test]
    fn undo_takes_back_only_this_authors_list_change() {
        let (mut a, mut b) = list_pair(&["s1", "s2", "s3"]);
        let ua = a.list_move("slides", "s3", 0).expect("A moves s3 up");
        let ub = b.list_insert("slides", 3, "s4").expect("B adds s4");
        exchange(&mut a, &mut b, &ua, &ub);
        let undo = a.undo_local().expect("A undoes its move");
        b.apply_doc_update(&undo).expect("B");
        assert_eq!(a.list_ids("slides"), ids(&["s1", "s2", "s3", "s4"]));
        assert_eq!(a.list_ids("slides"), b.list_ids("slides"));
        assert!(a.undo_local().is_none(), "the seed and B's insert are not A's");
    }

    #[test]
    fn lists_changed_reports_a_peers_change() {
        let (mut a, mut b) = list_pair(&["s1"]);
        assert_eq!(b.lists_changed(), vec!["slides".to_string()]);
        assert!(b.lists_changed().is_empty());
        let u = a.list_insert("slides", 1, "s2").expect("insert");
        b.apply_doc_update(&u).expect("B");
        assert_eq!(b.lists_changed(), vec!["slides".to_string()]);
    }

    #[test]
    fn a_snapshot_carries_bodies_and_lists_to_a_joiner() {
        let (mut a, _) = pair(&[para("1", "hello")]);
        a.list_seed("slides", &ids(&["s1", "s2"])).expect("list");
        let mut joiner = TextMerge::new("c");
        joiner.apply_doc_update(&a.full_update()).expect("snapshot");
        assert_eq!(texts(&joiner), vec![("1".to_string(), "hello".to_string())]);
        assert_eq!(joiner.list_ids("slides"), ids(&["s1", "s2"]));
    }
}

#[cfg(test)]
mod object_tests {
    use super::*;

    const O: char = OBJECT_CHAR;

    fn pair(text: &str) -> (TextMerge, TextMerge) {
        let mut a = TextMerge::new("a");
        let mut b = TextMerge::new("b");
        let seed = a.seed_body(&[BodyParagraph { para: "p1".into(), text: text.into(), props: None }]).expect("seed");
        b.apply_doc_update(&seed).expect("B seeds");
        (a, b)
    }

    fn exchange(a: &mut TextMerge, b: &mut TextMerge, ua: &[u8], ub: &[u8]) {
        a.apply_doc_update(ub).expect("A applies");
        b.apply_doc_update(ua).expect("B applies");
    }

    fn obj(at: usize, payload: &str) -> (u32, String) {
        (at as u32, payload.to_string())
    }

    /// The paragraph as an app holds it: its text, with each object's payload in place of its char.
    fn shown(m: &TextMerge) -> String {
        let (text, objects) = (m.text("p1"), m.objects("p1"));
        text.char_indices()
            .map(|(i, c)| match objects.iter().find(|(at, _)| *at as usize == i) {
                Some((_, p)) => format!("[{p}]"),
                None => c.to_string(),
            })
            .collect()
    }

    #[test]
    fn two_objects_placed_at_once_in_one_paragraph_land_alike() {
        let (mut a, mut b) = pair("Quarterly plan");
        // A anchors "Quar"'s start, B "plan"'s start, neither having seen the other.
        let ua = a.sync_objects("p1", &format!("{O}Quarterly plan"), &[obj(0, "x")]).expect("A");
        let ub = b.sync_objects("p1", &format!("Quarterly {O}plan"), &[obj(10, "y")]).expect("B");
        exchange(&mut a, &mut b, &ua, &ub);
        assert_eq!(shown(&a), shown(&b));
        assert_eq!(shown(&a), "[x]Quarterly [y]plan");
    }

    #[test]
    fn an_object_inserted_before_one_a_peer_deletes_survives_alone() {
        let (mut a, mut b) = pair("ab");
        let seed = a.sync_objects("p1", &format!("a{O}b"), &[obj(1, "y")]).expect("Y");
        b.apply_doc_update(&seed).expect("B has Y");
        // A puts X right before Y; B deletes Y meanwhile.
        let ua = a.sync_objects("p1", &format!("a{O}{O}b"), &[obj(1, "x"), obj(4, "y")]).expect("A");
        let ub = b.sync_objects("p1", "ab", &[]).expect("B");
        exchange(&mut a, &mut b, &ua, &ub);
        assert_eq!(shown(&a), shown(&b));
        assert_eq!(shown(&a), "a[x]b", "exactly X is left");
    }

    #[test]
    fn an_object_keeps_its_payload_across_a_split_and_a_join() {
        let (mut a, mut b) = pair("onetwo");
        let u = a.sync_objects("p1", &format!("one{O}two"), &[obj(3, "x")]).expect("x");
        b.apply_doc_update(&u).expect("B");
        // Split right before the object, then join back.
        let u = a.local_split("p1", 3, "p2", None).expect("split");
        b.apply_doc_update(&u).expect("B split");
        assert_eq!(b.objects("p2"), vec![obj(0, "x")], "the object moved with its text");
        assert!(b.objects("p1").is_empty());
        let u = b.local_join("p2").expect("join");
        a.apply_doc_update(&u).expect("A join");
        assert_eq!(shown(&a), shown(&b));
        assert_eq!(shown(&a), "one[x]two");
    }

    #[test]
    fn typing_after_an_object_is_plain_text() {
        let (mut a, mut b) = pair("ab");
        let u = a.sync_objects("p1", &format!("a{O}b"), &[obj(1, "x")]).expect("x");
        b.apply_doc_update(&u).expect("B");
        let u = b.local_edit_exact("p1", 4, 0, "typed").expect("type");
        a.apply_doc_update(&u).expect("A");
        assert_eq!(shown(&a), "a[x]typedb");
        assert_eq!(a.objects("p1"), vec![obj(1, "x")], "the typed text took no payload");
    }

    #[test]
    fn undo_takes_an_object_back_everywhere() {
        let (mut a, mut b) = pair("ab");
        let u = a.sync_objects("p1", &format!("a{O}b"), &[obj(1, "x")]).expect("x");
        b.apply_doc_update(&u).expect("B");
        let u = a.undo_local().expect("undo");
        b.apply_doc_update(&u).expect("B undo");
        assert_eq!((shown(&a), shown(&b)), ("ab".into(), "ab".into()));
    }

    #[test]
    fn bold_over_an_object_keeps_its_payload() {
        let (mut a, mut b) = pair("ab");
        let u = a.sync_objects("p1", &format!("a{O}b"), &[obj(1, "x")]).expect("x");
        b.apply_doc_update(&u).expect("B");
        let u = b.local_bold("p1", 0, 5, true).expect("bold");
        a.apply_doc_update(&u).expect("A");
        assert_eq!(a.objects("p1"), vec![obj(1, "x")]);
        assert_eq!(a.bold_spans("p1"), vec![(0, 5)]);
    }

    #[test]
    fn a_sync_touches_only_what_changed() {
        let (mut a, mut b) = pair("ab");
        let u = a.sync_objects("p1", &format!("a{O}b"), &[obj(1, "x")]).expect("x");
        b.apply_doc_update(&u).expect("B");
        assert!(a.sync_objects("p1", &format!("a{O}b"), &[obj(1, "x")]).is_none(), "nothing changed");
        // A types far from the object while B deletes it: A's sync must not bring it back.
        let ua = a.sync_objects("p1", &format!("a{O}b and more"), &[obj(1, "x")]).expect("A");
        let ub = b.sync_objects("p1", "ab", &[]).expect("B");
        exchange(&mut a, &mut b, &ua, &ub);
        assert_eq!(shown(&a), shown(&b));
        assert_eq!(shown(&a), "ab and more");
    }

    #[test]
    fn a_bare_object_char_is_tagged_by_its_first_sync() {
        let (mut a, mut b) = pair(&format!("a{O}b"));
        assert!(a.objects("p1").is_empty(), "seeded before objects travelled: bare");
        let u = a.sync_objects("p1", &format!("a{O}b"), &[obj(1, "x")]).expect("tag");
        b.apply_doc_update(&u).expect("B");
        assert_eq!(b.objects("p1"), vec![obj(1, "x")]);
        assert_eq!(b.text("p1"), format!("a{O}b"));
    }
}
