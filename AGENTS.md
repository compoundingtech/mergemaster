# Merge rule

Send a Fractal message to `agent/compoundingtech/mergemaster`.
Subject starts with `GO compoundingtech/mergemaster#N` or `NO-GO compoundingtech/mergemaster#N`; `Re: ` and `SOURCE ` prefixes are allowed.
Content must contain the full 40-hex head SHA; without it the message is ignored. Casual content verdicts and GitHub comments do not count.

- Require one independent reviewer's latest GO at the current head; any latest NO-GO blocks. Resolve refs from read-only current/archive listings, without marking mail read.
- Compute `.github/` and `iac/` changes locally; require a named second independent GO for either.
- Require every exact-head check-run to finish success/skipped and hosted CI to pass; explain reruns.
- Read CI's tested merge from checkout logs; refuse overlapping changes since its first-parent base.
- Require an open, non-draft, mergeable PR, approved head, current merge parents, and matching local merge-tree.
- Recheck refs and verdicts before merging; refuse anything unreadable or uncomputable.
- Keep Cargo test auto-discovery enabled so every `crates/*/tests/*.rs` runs.

From a trusted base checkout, use `scripts/merge-pr N --go-head SHA --go-ref message/ID --dry-run` with the agent gh config. Omit `--dry-run` to merge; see `--help` for details.
