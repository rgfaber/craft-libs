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
//! Offsets are bytes (yrs's default), which matches the apps' byte offsets.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use yrs::types::Attrs;
use yrs::undo::{Options as UndoOptions, UndoManager};
use yrs::updates::decoder::Decode;
use yrs::{Any, Assoc, Doc, GetString, IndexedSequence, Options, Origin, Out, ReadTxn, StickyIndex, Text, TextRef, Transact, Update};

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
        let undo = UndoManager::with_scope_and_options(&doc, &body, options);
        TextMerge { doc, body, origin, undo, outside: HashSet::new() }
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

    fn slots<T: ReadTxn>(&self, txn: &T) -> Vec<Slot> {
        let mut slots: Vec<Slot> = Vec::new();
        let mut pos = 0u32;
        for chunk in self.body().diff(txn, |_| ()) {
            let Some(s) = out_text(&chunk.insert) else { continue };
            let attrs = chunk.attributes.as_deref();
            match attrs.and_then(|a| a.get(PID)).and_then(any_string) {
                Some(pid) => {
                    let props = attrs.and_then(|a| a.get(PROPS)).and_then(any_string);
                    // Each leader is its own paragraph (adjacent leaders
                    // never share a chunk: their ids differ).
                    for (i, _) in s.char_indices() {
                        slots.push(Slot { para: pid.clone(), leader_at: pos + i as u32, text: String::new(), props: props.clone() });
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

    fn slot(&self, para: &str) -> Option<Slot> {
        let txn = self.doc.transact();
        self.slots(&txn).into_iter().find(|s| s.para == para)
    }

    /// Whether the body holds this paragraph.
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
        let body = self.body();
        let mut txn = self.doc.transact_mut();
        let mut at = 0u32;
        for p in paras {
            body.insert_with_attributes(&mut txn, at, LEADER, leader_attrs(&p.para, p.props.as_deref()));
            at += LEADER.len() as u32;
            if !p.text.is_empty() {
                body.insert_with_attributes(&mut txn, at, &p.text, plain_attrs());
                at += p.text.len() as u32;
            }
        }
        Some(txn.encode_update_v1())
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
        self.undo.reset();
        let (text, base, len) = match self.slot(para) {
            Some(slot) => (self.body(), slot.start(), slot.text.len() as u32),
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

    /// Splits body paragraph `para` at byte `at`: everything after `at`
    /// becomes the new paragraph `new_para` (with `props`). One leader is
    /// inserted; no text moves, so concurrent typing anywhere survives and
    /// two concurrent splits make three paragraphs, never a duplicate.
    pub fn local_split(&mut self, para: &str, at: u32, new_para: &str, props: Option<&str>) -> Option<Vec<u8>> {
        let slot = self.slot(para)?;
        if self.in_body(new_para) {
            return None;
        }
        self.undo.reset();
        let at = at.min(slot.text.len() as u32);
        let body = self.body();
        let mut txn = self.doc.transact_mut_with(self.origin.clone());
        body.insert_with_attributes(&mut txn, slot.start() + at, LEADER, leader_attrs(new_para, props));
        Some(txn.encode_update_v1())
    }

    /// Joins body paragraph `para` onto the paragraph before it (Backspace
    /// at its start, Delete at the end of the one before): its leader goes,
    /// so its text — including anything typed into it concurrently — joins
    /// the previous paragraph. `None` for the first paragraph or an unknown one.
    pub fn local_join(&mut self, para: &str) -> Option<Vec<u8>> {
        let slots = self.body_paragraphs();
        let first = slots.first().map(|s| s.para.clone());
        if first.as_deref() == Some(para) {
            return None;
        }
        let slot = self.slot(para)?;
        self.undo.reset();
        let body = self.body();
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
        let body = self.body();
        let stickies: Vec<Option<StickyIndex>> = {
            let slots = self.slots(&self.doc.transact());
            let mut txn = self.doc.transact_mut();
            positions
                .iter()
                .map(|(para, off)| {
                    let slot = slots.iter().find(|s| &s.para == para)?;
                    let at = slot.start() + (*off).min(slot.text.len() as u32);
                    // Before: the position belongs to the character before it
                    // (the leader, at a paragraph's start).
                    body.sticky_index(&mut txn, at, Assoc::Before)
                })
                .collect()
        };
        {
            let mut txn = self.doc.transact_mut();
            txn.apply_update(update).map_err(|e| format!("{e:?}"))?;
        }
        let txn = self.doc.transact();
        let slots = self.slots(&txn);
        Ok(positions
            .iter()
            .zip(stickies)
            .map(|((para, off), sticky)| {
                let Some(index) = sticky.and_then(|s| s.get_offset(&txn)).map(|o| o.index) else {
                    return (para.clone(), *off);
                };
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
        self.undo.reset();
        let (text, base, total) = match self.slot(para) {
            Some(slot) => (self.body(), slot.start(), slot.text.len() as u32),
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
        let outside = (!self.in_body(para)).then(|| self.doc.get_or_insert_text(para.to_string()));
        let txn = self.doc.transact();
        let (chunks, range) = match (&outside, self.slots(&txn).into_iter().find(|s| s.para == para)) {
            (None, Some(slot)) => (self.body().diff(&txn, |_| ()), Some((slot.start(), slot.start() + slot.text.len() as u32))),
            (Some(text), _) => (text.diff(&txn, |_| ()), None),
            (None, None) => return Vec::new(),
        };
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
    [(Arc::<str>::from(PID), Any::Null), (Arc::<str>::from(PROPS), Any::Null)].into_iter().collect()
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
}
