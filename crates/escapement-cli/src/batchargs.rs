//! `batch --recipients ID:TOTAL[:CLIFF],...`: who gets what in one `BatchCreate`, read and checked before anything is
//! built. With `--cliff START,CLIFF,END` each recipient gives its own cliff amount (`ID:TOTAL:CLIFF`), so that a
//! recipient's cliff is never another's absolute amount; with `--linear` there is none (`ID:TOTAL`).

use anyhow::{bail, Context, Result};

/// One recipient as given: its account (parsed by the caller), its total and, in a cliff batch, its cliff amount.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Recipient {
    pub id: String,
    pub total: u128,
    pub cliff: Option<u128>,
}

/// Reads `--recipients`. Each part is trimmed; an empty part (a stray comma) is refused, as is a part without exactly
/// the fields the batch's shape needs, an amount that is not a number, a cliff above its total, and, unless
/// `allow_duplicates`, an account named twice. Zero totals are left to `zero_totals_refused` (the program refuses them
/// too, which `--no-precheck` lets the end-to-end suite show).
pub fn parse_recipients(
    s: &str,
    with_cliff: bool,
    allow_duplicates: bool,
) -> Result<Vec<Recipient>> {
    if s.trim().is_empty() {
        bail!("--recipients: no recipient");
    }
    let mut out: Vec<Recipient> = Vec::new();
    for part in s.split(',') {
        let part = part.trim();
        if part.is_empty() {
            bail!("--recipients: an empty recipient (a stray comma?)");
        }
        let fields: Vec<&str> = part.split(':').map(str::trim).collect();
        let (id, total, cliff) = match (with_cliff, fields.as_slice()) {
            (false, [id, total]) => (*id, *total, None),
            (true, [id, total, cliff]) => (*id, *total, Some(*cliff)),
            (false, _) => bail!("--recipients {part:?}: expected ID:TOTAL"),
            (true, _) => bail!(
                "--recipients {part:?}: expected ID:TOTAL:CLIFF (a cliff batch gives each recipient its cliff amount)"
            ),
        };
        if id.is_empty() {
            bail!("--recipients {part:?}: no account");
        }
        let total: u128 = total.parse().with_context(|| {
            format!("--recipients {part:?}: the total {total:?} is not an amount")
        })?;
        let cliff = match cliff {
            Some(c) => {
                let c: u128 = c.parse().with_context(|| {
                    format!("--recipients {part:?}: the cliff {c:?} is not an amount")
                })?;
                if c > total {
                    bail!("--recipients {part:?}: the cliff amount {c} is above the total {total}");
                }
                Some(c)
            }
            None => None,
        };
        if !allow_duplicates && out.iter().any(|r| r.id == id) {
            bail!("--recipients: {id} is named twice (pass --allow-duplicates if that is meant)");
        }
        out.push(Recipient {
            id: id.to_string(),
            total,
            cliff,
        });
    }
    Ok(out)
}

/// The SDK's check before simulation: every recipient gets something.
pub fn zero_totals_refused(recipients: &[Recipient]) -> Result<()> {
    if let Some(r) = recipients.iter().find(|r| r.total == 0) {
        bail!("--recipients: {} gets a zero total", r.id);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn r(id: &str, total: u128, cliff: Option<u128>) -> Recipient {
        Recipient {
            id: id.to_string(),
            total,
            cliff,
        }
    }

    #[test]
    fn linear_recipients_are_trimmed_and_read_in_order() {
        assert_eq!(
            parse_recipients(" A:60 , B:40,C : 20 ", false, false).unwrap(),
            vec![r("A", 60, None), r("B", 40, None), r("C", 20, None)]
        );
    }

    #[test]
    fn a_cliff_batch_gives_each_recipient_its_own_cliff() {
        assert_eq!(
            parse_recipients("A:60:20,B:40:10", true, false).unwrap(),
            vec![r("A", 60, Some(20)), r("B", 40, Some(10))]
        );
    }

    #[test]
    fn malformed_recipients_are_refused_with_the_part_named() {
        for (s, cliff, why) in [
            ("", false, "no recipient"),
            ("A:1,", false, "stray comma"),
            ("A:1,,B:2", false, "stray comma"),
            ("A", false, "expected ID:TOTAL"),
            ("A:1:1", false, "expected ID:TOTAL"),
            ("A:1", true, "expected ID:TOTAL:CLIFF"),
            (":5", false, "no account"),
            ("A:x", false, "not an amount"),
            ("A:-1", false, "not an amount"),
            ("A:10:x", true, "not an amount"),
            ("A:10:11", true, "above the total"),
            ("A:1,B:2,A:3", false, "named twice"),
        ] {
            let err = parse_recipients(s, cliff, false).unwrap_err().to_string();
            assert!(err.contains(why), "{s:?}: {err}");
        }
    }

    #[test]
    fn duplicates_pass_only_when_meant() {
        assert_eq!(parse_recipients("A:1,A:2", false, true).unwrap().len(), 2);
    }

    #[test]
    fn zero_totals_are_a_precheck() {
        let rs = parse_recipients("A:5,B:0", false, false).unwrap();
        assert!(zero_totals_refused(&rs)
            .unwrap_err()
            .to_string()
            .contains("B gets a zero total"));
        assert!(zero_totals_refused(&rs[..1]).is_ok());
    }
}
