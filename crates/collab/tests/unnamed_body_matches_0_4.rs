//! The unnamed body is what 0.4 shipped: a 0.4 replica and one of this
//! version edit one document together, through the 0.2 Enter/join races,
//! the register and undo, and both read the same after every exchange.

use macula_craft_seam::text::{BodyParagraph, TextMerge};
use seam04::text::{BodyParagraph as BodyParagraph04, TextMerge as TextMerge04};

fn texts(m: &TextMerge) -> Vec<(String, String)> {
    m.body_paragraphs().into_iter().map(|p| (p.para, p.text)).collect()
}

fn texts04(m: &TextMerge04) -> Vec<(String, String)> {
    m.body_paragraphs().into_iter().map(|p| (p.para, p.text)).collect()
}

/// A new replica seeds, an 0.4 one joins; then the other way round.
fn pairs(paras: &[(&str, &str)]) -> Vec<(TextMerge, TextMerge04)> {
    let new = paras.iter().map(|(p, t)| BodyParagraph { para: p.to_string(), text: t.to_string(), props: None }).collect::<Vec<_>>();
    let old = paras.iter().map(|(p, t)| BodyParagraph04 { para: p.to_string(), text: t.to_string(), props: None }).collect::<Vec<_>>();
    let mut a = TextMerge::new("a");
    let mut b = TextMerge04::new("b");
    b.apply_doc_update(&a.seed_body(&new).expect("seed")).expect("0.4 joins");
    let mut c = TextMerge::new("a");
    let mut d = TextMerge04::new("b");
    c.apply_doc_update(&d.seed_body(&old).expect("0.4 seeds")).expect("joins 0.4");
    vec![(a, b), (c, d)]
}

#[test]
fn concurrent_enters_and_a_join_converge_across_versions() {
    for (mut a, mut b) in pairs(&[("1", "aaaa bbbb cccc"), ("2", "two")]) {
        let ua = a.local_split("1", 5, "10", None).expect("new presses Enter");
        let ub = b.local_split("1", 10, "20", None).expect("0.4 presses Enter");
        a.apply_doc_update(&ub).expect("new applies");
        b.apply_doc_update(&ua).expect("0.4 applies");
        assert_eq!(texts(&a), texts04(&b));
        assert_eq!(texts(&a).len(), 4);
        let ua = a.local_join("2").expect("new joins");
        let ub = b.local_edit_exact("2", 3, 0, " and three").expect("0.4 types into 2");
        a.apply_doc_update(&ub).expect("new applies");
        b.apply_doc_update(&ua).expect("0.4 applies");
        assert_eq!(texts(&a), texts04(&b));
        assert!(texts(&a).iter().any(|(_, t)| t.ends_with("two and three")), "{:?}", texts(&a));
    }
}

#[test]
fn bold_register_and_undo_agree_across_versions() {
    for (mut a, mut b) in pairs(&[("p1", "Bravo. Alpha. ")]) {
        let ub = b.local_bold("p1", 7, 6, true).expect("0.4 bolds");
        let ua = a.local_edit_exact("p1", 10, 0, "ONE ").expect("new types");
        a.apply_doc_update(&ub).expect("new");
        b.apply_doc_update(&ua).expect("0.4");
        assert_eq!(a.text("p1"), b.text("p1"));
        assert_eq!(a.bold_spans("p1"), b.bold_spans("p1"));
        let ua = a.register_set("cell", "1").expect("new writes");
        let ub = b.register_set("cell", "2").expect("0.4 writes");
        a.apply_doc_update(&ub).expect("new");
        b.apply_doc_update(&ua).expect("0.4");
        assert_eq!(a.register_get("cell"), b.register_get("cell"));
        let undo = a.undo_local().expect("new undoes its write");
        b.apply_doc_update(&undo).expect("0.4");
        assert_eq!(a.register_entries(), b.register_entries());
        assert_eq!(a.text("p1"), b.text("p1"));
    }
}

#[test]
fn a_snapshot_crosses_versions_both_ways() {
    for (a, b) in pairs(&[("1", "one"), ("2", "two")]) {
        let mut new_joiner = TextMerge::new("c");
        new_joiner.apply_doc_update(&b.full_update()).expect("from 0.4");
        let mut old_joiner = TextMerge04::new("d");
        old_joiner.apply_doc_update(&a.full_update()).expect("from new");
        assert_eq!(texts(&new_joiner), texts04(&old_joiner));
    }
}
