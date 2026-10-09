//! Paragraph text merge: one CRDT text per stable paragraph id, so
//! concurrent typing converges; per-author undo reverts only the local
//! author's own edits, tracked per origin by yrs's own undo manager.
//!
//! The spike uses `yrs` (Yjs's Rust implementation) with its default
//! byte-offset text indexing, which matches the apps' byte offsets.

use std::collections::{HashMap, HashSet};

use yrs::types::Attrs;
use yrs::undo::{Options as UndoOptions, UndoManager};
use yrs::updates::decoder::Decode;
use yrs::{Any, Doc, GetString, Options, Origin, Out, ReadTxn, Text, TextRef, Transact, Update};

/// The text CRDT for one document: paragraph id -> text, plus one undo
/// manager per paragraph, scoped to this author's origin.
pub struct TextMerge {
    doc: Doc,
    /// This author's transaction origin: what its undo managers track.
    origin: Origin,
    managers: HashMap<String, UndoManager<()>>,
}

impl TextMerge {
    /// A merge for one author (whose edits it can undo).
    pub fn new(author: &str) -> Self {
        TextMerge { doc: Doc::with_options(Options::default()), origin: Origin::from(author.to_string()), managers: HashMap::new() }
    }

    fn text_ref(&self, para: &str) -> TextRef {
        self.doc.get_or_insert_text(para.to_string())
    }

    /// The undo manager scoped to `para`, created before the transaction it
    /// must observe.
    fn manager(&mut self, para: &str) -> &mut UndoManager<()> {
        let doc = self.doc.clone();
        let origin = self.origin.clone();
        let name = para.to_string();
        self.managers.entry(name).or_insert_with(move || {
            let text = doc.get_or_insert_text(para.to_string());
            let options = UndoOptions { tracked_origins: HashSet::from([origin]), ..UndoOptions::default() };
            UndoManager::with_scope_and_options(&doc, &text, options)
        })
    }

    /// The merged text of a paragraph.
    pub fn text(&self, para: &str) -> String {
        let text = self.text_ref(para);
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
    /// text.
    pub fn local_edit_exact(&mut self, para: &str, index: u32, remove_len: u32, insert: &str) -> Option<Vec<u8>> {
        if remove_len == 0 && insert.is_empty() {
            return None;
        }
        // The manager must exist before the transaction, or it misses it;
        // reset ends the previous capture window, so one command is one
        // undo step.
        self.manager(para).reset();
        let len = self.text(para).len() as u32;
        let index = index.min(len);
        let remove_len = remove_len.min(len - index);
        if remove_len == 0 && insert.is_empty() {
            return None;
        }
        let update = {
            let text = self.text_ref(para);
            let mut txn = self.doc.transact_mut_with(self.origin.clone());
            if remove_len > 0 {
                text.remove_range(&mut txn, index, remove_len);
            }
            if !insert.is_empty() {
                text.insert(&mut txn, index, insert);
            }
            txn.encode_update_v1()
        };
        Some(update)
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

    /// Every change this CRDT holds, from the beginning: what a joining peer
    /// needs to seed an empty CRDT to this state.
    pub fn full_update(&self) -> Vec<u8> {
        let txn = self.doc.transact();
        txn.encode_state_as_update_v1(&yrs::StateVector::default())
    }

    /// Applies a document-wide update (a seed or a sync); the caller
    /// reconciles whatever paragraphs it changed.
    pub fn apply_doc_update(&mut self, update: &[u8]) -> Result<(), String> {
        let update = Update::decode_v1(update).map_err(|e| format!("{e:?}"))?;
        let mut txn = self.doc.transact_mut();
        txn.apply_update(update).map_err(|e| format!("{e:?}"))
    }

    /// Applies a bold change over `[index, index+len)` as a CRDT attribute:
    /// the formatting travels with the text items, so it covers exactly the
    /// characters the author covered, whatever concurrent inserts land.
    /// Returns the update to broadcast, `None` when nothing changed.
    pub fn local_bold(&mut self, para: &str, index: u32, len: u32, bold: bool) -> Option<Vec<u8>> {
        if len == 0 {
            return None;
        }
        self.manager(para).reset();
        let total = self.text(para).len() as u32;
        let index = index.min(total);
        let len = len.min(total - index);
        if len == 0 {
            return None;
        }
        let value = if bold { Any::Bool(true) } else { Any::Null };
        let attrs: Attrs = [(std::sync::Arc::<str>::from("bold"), value)].into_iter().collect();
        let update = {
            let text = self.text_ref(para);
            let mut txn = self.doc.transact_mut_with(self.origin.clone());
            text.format(&mut txn, index, len, attrs);
            txn.encode_update_v1()
        };
        Some(update)
    }

    /// The bold spans (byte ranges) the CRDT currently holds for `para`, in
    /// order: the item-anchored truth every replica can derive runs from.
    pub fn bold_spans(&self, para: &str) -> Vec<(u32, u32)> {
        let text = self.text_ref(para);
        let txn = self.doc.transact();
        let mut spans = Vec::new();
        let mut pos = 0u32;
        for chunk in text.diff(&txn, |_| ()) {
            let Some(s) = out_text(&chunk.insert) else { continue };
            let bold = chunk.attributes.as_deref().and_then(|a| a.get("bold")).is_some_and(|v| matches!(v, Any::Bool(true)));
            let n = s.len() as u32;
            if bold && n > 0 {
                spans.push((pos, pos + n));
            }
            pos += n;
        }
        spans
    }

    /// Applies a peer's update; returns the merged text of `para`.
    pub fn apply_update(&mut self, para: &str, update: &[u8]) -> Result<String, String> {
        let update = Update::decode_v1(update).map_err(|e| format!("{e:?}"))?;
        // The text must exist before an update for it integrates cleanly.
        let _ = self.text_ref(para);
        {
            let mut txn = self.doc.transact_mut();
            txn.apply_update(update).map_err(|e| format!("{e:?}"))?;
        }
        Ok(self.text(para))
    }

    /// Undoes the most recent local edit: the paragraph, the update to
    /// broadcast and the merged text after the undo. Nothing when the local
    /// author has no edit to undo.
    pub fn undo_local(&mut self) -> Option<(String, Vec<u8>, String)> {
        let paras: Vec<String> = self.managers.keys().cloned().collect();
        for para in paras {
            let can_undo = match self.managers.get(&para) {
                Some(m) => m.can_undo(),
                None => false,
            };
            if !can_undo {
                continue;
            }
            let before = self.doc.transact().state_vector();
            let undone = match self.managers.get_mut(&para) {
                Some(m) => m.undo_blocking(),
                None => false,
            };
            if !undone {
                continue;
            }
            let update = {
                let txn = self.doc.transact();
                txn.encode_state_as_update_v1(&before)
            };
            return Some((para.clone(), update, self.text(&para)));
        }
        None
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

    #[test]
    fn two_editors_converge() {
        let mut a = TextMerge::new("a");
        let mut b = TextMerge::new("b");

        // A and B type into the same empty paragraph, before hearing from
        // each other.
        let ua = a.local_edit("p1", "", "Hello ").expect("A's edit is an update");
        let ub = b.local_edit("p1", "", "world").expect("B's edit is an update");

        // Exchange, both orders.
        let ta = a.apply_update("p1", &ub).expect("A applies B");
        let tb = b.apply_update("p1", &ua).expect("B applies A");
        assert_eq!(ta, tb, "both sides converge to the same text");
        assert!(ta.contains("Hello ") && ta.contains("world"), "neither edit was lost: {ta:?}");
        assert_eq!(a.text("p1"), ta);
        assert_eq!(b.text("p1"), ta);

        // Interleaved edits at both ends converge too.
        let ua2 = a.local_edit("p1", &ta, &format!("{ta}!")).expect("A appends");
        let ub2 = b.local_edit("p1", &ta, &format!("?{ta}")).expect("B prepends");
        let ta2 = a.apply_update("p1", &ub2).expect("A applies B again");
        let tb2 = b.apply_update("p1", &ua2).expect("B applies A again");
        assert_eq!(ta2, tb2, "interleaved edits converge");
        assert_eq!(a.text("p1"), ta2);
        assert_eq!(b.text("p1"), ta2);
    }

    #[test]
    fn bold_is_anchored_to_the_text_it_covers() {
        let mut a = TextMerge::new("a");
        let mut b = TextMerge::new("b");
        // A types, B hears it.
        let u = a.local_edit_exact("p1", 0, 0, "Bravo. Alpha. ").expect("text");
        let _ = b.apply_update("p1", &u).expect("B applies");

        // B bolds "Alpha." (bytes 7..13).
        let ub = b.local_bold("p1", 7, 6, true).expect("bold");
        // A inserts "ONE " inside that span before hearing about the bold.
        let ua = a.local_edit_exact("p1", 10, 0, "ONE ").expect("insert");
        // Adversarial exchange order: B's bold lands at A after its insert,
        // A's insert lands at B after B's bold.
        let _ = a.apply_update("p1", &ub).expect("A applies bold");
        let _ = b.apply_update("p1", &ua).expect("B applies insert");

        assert_eq!(a.text("p1"), b.text("p1"), "text converged");
        assert_eq!(a.bold_spans("p1"), b.bold_spans("p1"), "the bold covers the same characters on both: item-anchored");
        assert!(!a.bold_spans("p1").is_empty(), "and it is still there");
    }

    #[test]
    fn undo_is_per_author() {
        let mut a = TextMerge::new("a");
        let mut b = TextMerge::new("b");

        let ua = a.local_edit("p1", "", "Hello ").expect("A's edit");
        let ub = b.local_edit("p1", "", "world").expect("B's edit");
        let _ = a.apply_update("p1", &ub).expect("A applies B");
        let _ = b.apply_update("p1", &ua).expect("B applies A");
        assert_eq!(a.text("p1"), b.text("p1"));

        // A undoes: only A's own text goes; B's survives, on both sides.
        let (para, update, merged) = a.undo_local().expect("A has something to undo");
        assert_eq!(para, "p1");
        assert_eq!(merged, "world", "only A's own edit was undone: {merged:?}");
        assert_eq!(a.text("p1"), "world");
        let tb = b.apply_update("p1", &update).expect("B applies the undo");
        assert_eq!(tb, "world");
        assert_eq!(b.text("p1"), "world");
    }

    #[test]
    fn undo_survives_interleaved_edits() {
        let mut a = TextMerge::new("a");
        let mut b = TextMerge::new("b");

        // A and B each type a full sentence into the same empty paragraph.
        // The typed edit is exact (caret + text), as the app captures it —
        // not a text diff, which is ambiguous here.
        let ua = a.local_edit_exact("p1", 0, 0, "Hello from Alice. ").expect("A's edit");
        let _ = b.apply_update("p1", &ua).expect("B applies A");
        let ub = b.local_edit_exact("p1", 0, 0, "Hi from Bob. ").expect("B's edit");
        let _ = a.apply_update("p1", &ub).expect("A applies B");
        assert_eq!(a.text("p1"), b.text("p1"));

        // A undoes first; B's text survives.
        let (_, update, merged) = a.undo_local().expect("A undoes");
        let _ = b.apply_update("p1", &update).expect("B applies A's undo");
        assert_eq!(merged, "Hi from Bob. ", "A's undo left only B's text: {merged:?}");
        assert_eq!(b.text("p1"), "Hi from Bob. ");

        // B undoes too; now nothing is left.
        let (_, update, merged) = b.undo_local().expect("B undoes");
        let _ = a.apply_update("p1", &update).expect("A applies B's undo");
        assert_eq!(merged, "");
        assert_eq!(a.text("p1"), "");
    }
}
