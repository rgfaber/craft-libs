//! Paragraph text merge: one CRDT text per stable paragraph id, so
//! concurrent typing converges; per-author undo reverts only the local
//! author's own last edit.
//!
//! The spike uses `yrs` (Yjs's Rust implementation) with its default
//! byte-offset text indexing, which matches the apps' byte offsets.

use yrs::updates::decoder::Decode;
use yrs::{Doc, GetString, Options, Text, TextRef, Transact, Update};

/// The text CRDT for one document: paragraph id -> text, plus the local
/// author's undo stack.
pub struct TextMerge {
    doc: Doc,
    undo: Vec<UndoEntry>,
}

/// One local edit, in the terms later undo needs.
#[derive(Clone, Debug)]
struct UndoEntry {
    para: String,
    index: u32,
    removed: String,
    inserted: String,
}

impl Default for TextMerge {
    fn default() -> Self {
        Self::new()
    }
}

impl TextMerge {
    pub fn new() -> Self {
        TextMerge { doc: Doc::with_options(Options::default()), undo: Vec::new() }
    }

    fn text_ref(&self, para: &str) -> TextRef {
        self.doc.get_or_insert_text(para.to_string())
    }

    /// The merged text of a paragraph.
    pub fn text(&self, para: &str) -> String {
        let text = self.text_ref(para);
        let txn = self.doc.transact();
        text.get_string(&txn)
    }

    /// Applies the local change `before -> after` to `para` and returns the
    /// CRDT update to broadcast, `None` when nothing changed.
    pub fn local_edit(&mut self, para: &str, before: &str, after: &str) -> Option<Vec<u8>> {
        let (index, removed, inserted) = splice(before, after);
        if removed.is_empty() && inserted.is_empty() {
            return None;
        }
        let update = {
            let text = self.text_ref(para);
            let mut txn = self.doc.transact_mut();
            if !removed.is_empty() {
                text.remove_range(&mut txn, index, removed.len() as u32);
            }
            if !inserted.is_empty() {
                text.insert(&mut txn, index, &inserted);
            }
            txn.encode_update_v1()
        };
        self.undo.push(UndoEntry { para: para.to_string(), index, removed, inserted });
        Some(update)
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
        let entry = self.undo.pop()?;
        let current = self.text(&entry.para);
        let update = {
            let text = self.text_ref(&entry.para);
            let mut txn = self.doc.transact_mut();
            if !entry.inserted.is_empty() {
                // The text this edit inserted, wherever it landed among a
                // peer's concurrent edits.
                let at = nearest(&current, &entry.inserted, entry.index);
                text.remove_range(&mut txn, at, entry.inserted.len() as u32);
                if !entry.removed.is_empty() {
                    // Put back what that edit had replaced, in its place.
                    text.insert(&mut txn, at, &entry.removed);
                }
            } else if !entry.removed.is_empty() {
                let at = entry.index.min(current.len() as u32);
                text.insert(&mut txn, at, &entry.removed);
            }
            txn.encode_update_v1()
        };
        let merged = self.text(&entry.para);
        Some((entry.para, update, merged))
    }
}

/// The single contiguous change from `before` to `after`: the byte index,
/// the removed text and the inserted text. Byte offsets, like the apps'.
fn splice(before: &str, after: &str) -> (u32, String, String) {
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

/// The occurrence of `needle` in `hay` closest to `at`; `at` clamped when
/// there is none.
fn nearest(hay: &str, needle: &str, at: u32) -> u32 {
    let mut best: Option<usize> = None;
    let mut from = 0;
    while let Some(i) = hay[from..].find(needle) {
        let pos = from + i;
        best = match best {
            Some(b) if (b as i64 - at as i64).abs() <= (pos as i64 - at as i64).abs() => Some(b),
            _ => Some(pos),
        };
        from = pos + 1;
        if from >= hay.len() {
            break;
        }
    }
    best.map(|b| b as u32).unwrap_or_else(|| at.min(hay.len() as u32))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn two_editors_converge() {
        let mut a = TextMerge::new();
        let mut b = TextMerge::new();

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
    fn undo_is_per_author() {
        let mut a = TextMerge::new();
        let mut b = TextMerge::new();

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
}
