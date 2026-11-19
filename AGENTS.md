# Merge rule

Send a Fractal message to `agent/compoundingtech/mergemaster`.
Subject starts with `GO compoundingtech/mergemaster#N` or `NO-GO compoundingtech/mergemaster#N`; `Re: ` and `SOURCE ` prefixes are allowed.
Content must contain the full 40-hex head SHA; without it the message is ignored. Casual content verdicts and GitHub comments do not count.
Only Mergemaster-authored PRs are supported: require `--author-agent agent/compoundingtech/mergemaster`; its GOs never count, but the author can withdraw by sending a `NO-GO` message to itself. Other authors need manual review.
- Require one independent reviewer's latest GO at the current head; any latest NO-GO blocks. Resolve refs from read-only current/archive listings, without marking mail read.
- Compute `.github/` and `iac/` changes locally; require a named second independent GO for either.
- Require every exact-head check-run to finish success/skipped and hosted CI to pass; explain reruns.
- Read CI's tested merge from checkout logs; refuse overlapping changes since its first-parent base.
- Require an open, non-draft, mergeable PR, approved head, current merge parents, and matching local merge-tree.
- Lock local runs and recheck main immediately before merging; another writer can still race the API call, so verify the merged first parent/tree afterward and report a revert command on mismatch.
- Keep Cargo test auto-discovery enabled so every `crates/*/tests/*.rs` runs.

From a trusted base checkout, use `scripts/merge-pr N --author-agent agent/compoundingtech/mergemaster --go-head SHA --go-ref message/ID --dry-run` with the agent gh config. Omit `--dry-run` to merge; see `--help` for details.
