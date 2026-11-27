//! Account-level Marmot membership gate.
//!
//! MDK reports one record per account, including when that account has several
//! MLS leaves. A sender-only group must not pass. An extra account must not
//! pass. Extra leaves of the sender or the configured recipient are the same
//! account id and stay allowed. A passing result is the roster observed at
//! this call. It is not a lock held across MDK's later encryption. The next
//! call can refuse a recipient the previous call allowed.

pub fn authorize_group_members(
    members: &[String],
    sender: &str,
    recipient: &str,
) -> Result<(), &'static str> {
    let sender = sender.trim().to_ascii_lowercase();
    let recipient = recipient.trim().to_ascii_lowercase();
    if sender.is_empty() || recipient.is_empty() {
        return Err("membership_unknown");
    }
    if sender == recipient {
        return Err("membership_rejected");
    }
    let members: Vec<String> = members
        .iter()
        .map(|member| member.trim().to_ascii_lowercase())
        .filter(|member| !member.is_empty())
        .collect();
    if members.is_empty() {
        return Err("membership_unknown");
    }
    if !members.iter().any(|member| member == &sender) {
        return Err("sender_absent");
    }
    if !members.iter().any(|member| member == &recipient) {
        return Err("recipient_absent");
    }
    if members
        .iter()
        .any(|member| member != &sender && member != &recipient)
    {
        return Err("membership_rejected");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sender_only_group_is_rejected_and_both_parties_are_required() {
        let sender = "aa".repeat(32);
        let recipient = "bb".repeat(32);
        let other = "cc".repeat(32);
        let sender_only = vec![sender.clone()];
        let recipient_only = vec![recipient.clone()];
        let intruder = vec![sender.clone(), recipient.clone(), other];
        let extra_leaf = vec![sender.clone(), sender.clone(), recipient.clone()];
        assert_eq!(
            authorize_group_members(&sender_only, &sender, &recipient),
            Err("recipient_absent")
        );
        assert_eq!(
            authorize_group_members(&recipient_only, &sender, &recipient),
            Err("sender_absent")
        );
        assert_eq!(
            authorize_group_members(&intruder, &sender, &recipient),
            Err("membership_rejected")
        );
        assert_eq!(
            authorize_group_members(&extra_leaf, &sender, &recipient),
            Ok(())
        );
    }

    #[test]
    fn a_later_roster_that_removes_the_recipient_does_not_keep_the_earlier_allowance() {
        let sender = "aa".repeat(32);
        let recipient = "bb".repeat(32);
        let present = vec![sender.clone(), recipient.clone()];
        let removed = vec![sender.clone()];
        let empty = Vec::<String>::new();
        assert_eq!(
            authorize_group_members(&present, &sender, &recipient),
            Ok(())
        );
        assert_eq!(
            authorize_group_members(&removed, &sender, &recipient),
            Err("recipient_absent")
        );
        assert_eq!(
            authorize_group_members(&empty, &sender, &recipient),
            Err("membership_unknown")
        );
    }
}
