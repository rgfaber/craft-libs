//! Author-scoped ids: one rule every Craft app mints its object ids by (sheets,
//! slides, shapes), so two authors adding at once never mint the same id.
//!
//! An id is `(tag << 32) | n` as a `u64`: `tag` is the author's tag (the first
//! 21 bits of their node id) and `n` the author's own counter, which the app
//! persists in the document so a restart never reuses one. Tag 0 is a
//! document that has never been shared, so existing ids keep their values.
//! Every id stays below 2^53, so a JSON number carries it exactly in any
//! language (a JavaScript client rounds anything above). At the seam an id
//! is its decimal string; the seam never interprets it.

/// The author's tag: the first 8 hex characters of the node id as a `u32`,
/// shifted right by 11 (21 bits). A node id whose top 21 bits are all zero
/// gets 1, so 0, the never-shared tag, only ever means an author that is not
/// a hex node id.
///
/// ```
/// assert_eq!(macula_craft_seam::author_tag("ffffffff00"), 0x1F_FFFF);
/// assert_eq!(macula_craft_seam::author_tag("00000800aa"), 1);
/// assert_eq!(macula_craft_seam::author_tag("000007ffaa"), 1, "never the never-shared tag");
/// assert_eq!(macula_craft_seam::author_tag("not hex!"), 0);
/// ```
pub fn author_tag(author: &str) -> u32 {
    author.get(..8).and_then(|prefix| u32::from_str_radix(prefix, 16).ok()).map_or(0, |v| (v >> 11).max(1))
}

/// The id an author mints: `(tag << 32) | n`, below 2^53 for any tag
/// [`author_tag`] returns.
///
/// ```
/// let id = macula_craft_seam::author_id(macula_craft_seam::author_tag("ffffffff"), u32::MAX);
/// assert!(id < 1 << 53);
/// assert_eq!(macula_craft_seam::author_id(0, 7), 7, "never shared: the old ids");
/// ```
pub fn author_id(tag: u32, n: u32) -> u64 {
    (u64::from(tag & 0x1F_FFFF) << 32) | u64::from(n)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn distinct_authors_get_distinct_tags_and_ids() {
        let (a, b) = (author_tag(&"ab".repeat(32)), author_tag(&"cd".repeat(32)));
        assert_ne!(a, b);
        assert_ne!(author_id(a, 1), author_id(b, 1), "the same counter, different authors");
        assert_ne!(author_id(a, 1), author_id(a, 2));
    }

    #[test]
    fn a_short_or_odd_author_is_tag_zero() {
        assert_eq!(author_tag(""), 0);
        assert_eq!(author_tag("abc"), 0);
        assert_eq!(author_tag("ééééééééé"), 0, "never slices inside a char");
    }
}
