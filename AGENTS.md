# Merge rule

Send a Fractal message to `agent/compoundingtech/mergemaster`; use the Fractal message sender (same-uid asserted identity), not server-verified identity.
Subject starts with `GO compoundingtech/mergemaster#N` or `NO-GO compoundingtech/mergemaster#N`; `Re: ` and `SOURCE ` prefixes are allowed.
Content must contain the full 40-hex head SHA; without it the message is ignored. Casual content verdicts and GitHub comments do not count.
Only Mergemaster-authored PRs are supported: require `--author-agent agent/compoundingtech/mergemaster`; its GOs never count, but the author can withdraw by sending a `NO-GO` message to itself. Other authors need manual review.
- Require one independent reviewer's latest GO at the current head; any latest NO-GO blocks. Resolve refs from read-only current/archive listings, without marking mail read.
- Compute `.github/` and `iac/` changes from main...head; require a named second independent GO for either.
- Require every exact-head check-run to finish success/skipped and hosted CI to pass; explain reruns of every workflow at the head.
- Verify CI's tested merge tree at its first-parent base; refuse overlap between CI-base..main changes and the PR's CI-base...head changes.
- Require an open, non-draft, mergeable PR, approved head, current merge parents, and matching local merge-tree.
- Refuse Johannes Schickling as author or committer in origin/main..head (name or schickling.j@gmail.com); re-author on a new signed agent branch or squash as Manager decides, and verify the merged commit's identities afterward, posting any miss on COORD.
- Lock local runs and recheck main immediately before merging; another writer can still race the API call, so verify the merged first parent/tree afterward and report a revert command on mismatch.
- Keep Cargo test auto-discovery enabled so every `crates/*/tests/*.rs` runs.
Trust model: agents on these hosts are assumed cooperative; this gate prevents mistakes, not a malicious same-uid agent.
From a trusted base checkout, use `scripts/merge-pr N --author-agent agent/compoundingtech/mergemaster --go-head SHA --go-ref message/ID --dry-run` with the agent gh config. Omit `--dry-run` to merge; see `--help` for details.
