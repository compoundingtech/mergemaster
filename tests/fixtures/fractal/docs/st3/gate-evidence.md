### Which checks skip today

| Check | `enforce` | `events` | `sample_one_in` | Since |
| --- | --- | --- | --- | --- |
| `typescript-client` | true | `pull_request` | 1 | this change |
| `fractal-web` (whole-check note; one shard's note never counts) | true | `pull_request` | 1 | 2026-10-23 |
| `linux-gate` | true | `pull_request` | 1 | 2026-10-23 |
| `genie-freshness` | true | `pull_request` | 1 | 2026-10-23 |
| `ci-script-tests` | true | `pull_request` | 1 | 2026-10-23 |

`typescript-client` was turned on after 48 hours of shadow decisions (2026-10-17 to 2026-10-19, 585 pull-request runs): 378 satisfied by a
trusted note, 254 of which would have skipped (the rest were sampled or touched a protected file), and not one satisfied note sat beside a failing
real job; the published notes' shadow verification (`evidence-shadow v1`) was `ok` for every lane in every merge-group run since it landed. The
sampled one in five kept comparing the note with a real run until 2026-10-26, when sampling was turned off for every check (Nathan: our pull
requests skip CI entirely; the merge queue's full run is the comparison). Each further check is its own reviewed change to this table, the policy and the
`enforced` lists in `ci-evidence-gate-test` and `evidence-verify-test`.

