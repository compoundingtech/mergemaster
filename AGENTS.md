# Merge rule

Use the trusted base checkout's `scripts/merge-pr`, never the PR's copy:

```sh
scripts/merge-pr NUMBER --go-head FULL_SHA --go-ref message/ID --dry-run
# Omit --dry-run only when every check passes.
```

- Binding verdicts are authenticated Fractal messages **to `agent/compoundingtech/mergemaster`**, not GitHub comments (agents share a GitHub login). A reviewer is the daemon-authenticated `from` agent, distinct from the author agent `agent/compoundingtech/mergemaster`. The tool reads both current and archived inboxes as Mergemaster; exact message reads can mark its own inbox read.
- Scope verdicts by `compoundingtech/mergemaster#NUMBER`, or `#NUMBER` together with `mergemaster`, in the message title/content. Use the reviewer's latest verdict by daemon `created_index`. Verdict words come from **content**, not quoted thread titles: GO counts only with the full current head or an 8+-hex prefix; NO-GO takes precedence. At least one independent reviewer's latest verdict must be an exact-head GO. Any reviewer's latest NO-GO blocks; only a later GO by that same reviewer clears it. An older-head GO neither counts nor blocks. `--go-ref` names an exact-head GO message whose sender still has a latest exact-head GO.
- The tool computes `.github/` and `iac/` touches from the actual base..head Git diff. Any touch requires `--second-go-ref message/ID` naming a distinct independent reviewer's exact-head GO, still current in that reviewer's latest verdict. A job in the PR's workflow is not this second review.
- All check-runs at the exact head, including earlier attempts, must be completed with `success` or `skipped`. The latest hosted `ci.yml` PR run must be successful, with successful GitHub-hosted jobs, on attempt 1 unless `--rerun-reason REASON` explicitly records why it was rerun.
- CI checkout logs must identify the merge commit actually tested. Its first parent is the CI base; its second parent must be the approved head. If changes from that CI base to current main overlap the PR's base..head changed files, require fresh CI.
- The PR must be open, non-draft and mergeable against main. Its head must equal the GO head. The advertised PR merge ref must have parents `(current main, head)` and the same tree as local `git merge-tree --write-tree main head`. Recheck mutable refs, verdicts and readiness before invoking `gh pr merge --merge --match-head-commit HEAD`.

Fail closed on unreadable messages, missing logs, or any uncomputable check. `--dry-run` reports each check as PASS/FAIL with evidence, performs no GitHub writes, and exits nonzero on refusal; it fetches Git objects locally. Use `GH_CONFIG_DIR=/home/schickling/.config/gh-assistant` for read-only tests/dry runs. Regression tests: `python3 tests/test-merge-pr.py`. Cargo auto-discovers all `crates/*/tests/*.rs`; do not disable automatic test targets.
