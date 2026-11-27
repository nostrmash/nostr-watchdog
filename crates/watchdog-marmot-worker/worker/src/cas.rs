//! Compare-and-swap outcome for one Durable Object account row.
//!
//! `rows_written == 1` is the proof that this writer changed the row.
//! Reading the stored revision afterwards is not proof: two callers can both
//! intend the same next revision, and only the update that matches the
//! previous revision is applied.

/// `stored_writer` is the writer id read after the conditional write.
///
/// A winning UPDATE reports `rows_written == 1`. Creating the account row
/// reports `rows_written == 2` in workerd while the row is visible with this
/// writer id and the intended revision. The random writer id is the proof
/// that this attempt owns the row. A losing writer reads the winner's id and
/// is rejected. Zero rows, or more than those two observed counts, is rejected.
#[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
pub fn commit_won(rows_written: usize, stored_writer: &str, our_writer: &str) -> bool {
    !our_writer.is_empty()
        && stored_writer == our_writer
        && (rows_written == 1 || rows_written == 2)
}

#[cfg(test)]
mod tests {
    use super::commit_won;

    #[test]
    fn a_losing_writer_is_rejected_when_the_next_revision_matches() {
        let stored_revision = 2u64;
        let intended_next = 2u64;
        assert_eq!(stored_revision, intended_next);
        assert!(commit_won(1, "winner", "winner"));
        assert!(commit_won(2, "winner", "winner"));
        assert!(!commit_won(0, "winner", "winner"));
        assert!(!commit_won(0, "winner", "loser"));
        assert!(!commit_won(1, "winner", "loser"));
        assert!(!commit_won(2, "winner", "loser"));
        assert!(!commit_won(3, "winner", "winner"));
    }
}
