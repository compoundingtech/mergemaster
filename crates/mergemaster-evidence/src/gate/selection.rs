//! Opt-in, BASE-owned PR lane selection. Uncovered paths select every lane.
use super::{
    config::{self, Policy},
    git,
};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};

#[derive(clap::Args)]
pub struct Args {
    #[arg(long)]
    pub base: String,
    #[arg(long)]
    pub head: String,
}

pub fn run(args: Args) -> Result<()> {
    let repo = std::env::current_dir()?;
    ensure!(
        config::full_commit(&args.head),
        "HEAD must be a full commit ID"
    );
    let config = config::load(&repo, &args.base)?;
    let result = match select(&repo, &args.base, &args.head, &config.policy)? {
        Some(selection) => serde_json::to_value(selection)?,
        None => {
            ensure!(
                git::text(&repo, &["cat-file", "-t", &args.head])? == "commit",
                "HEAD is not a commit"
            );
            serde_json::json!({"base": args.base, "head": args.head, "lanes": config.policy.lanes.keys().collect::<Vec<_>>(), "fallback_all": true})
        }
    };
    println!("{}", serde_json::to_string(&result)?);
    Ok(())
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PathSelection {
    pub always: Vec<String>,
    pub rules: Vec<PathRule>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PathRule {
    pub paths: Vec<String>,
    pub lanes: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct Selection {
    pub base: String,
    pub head: String,
    pub policy_sha256: String,
    pub changed_paths_sha256: String,
    pub lanes: Vec<String>,
    pub fallback_all: bool,
}

pub fn validate(policy: &Policy) -> Result<()> {
    let Some(selection) = &policy.path_selection else {
        return Ok(());
    };
    ensure!(
        selection.always.iter().any(|lane| lane == "review-go"),
        "path_selection.always must include review-go"
    );
    let review = policy.lanes.get("review-go");
    ensure!(
        review.is_some_and(|lane| lane.mode == "required_evidence"
            && lane.events.iter().any(|event| event == "pull_request")),
        "path_selection requires a required pull_request review-go lane"
    );
    let valid_lanes = |lanes: &[String]| -> Result<()> {
        ensure!(!lanes.is_empty(), "empty path selection lanes");
        let mut seen = BTreeSet::new();
        for lane in lanes {
            ensure!(
                policy.lanes.contains_key(lane) && seen.insert(lane),
                "unknown or duplicate path selection lane"
            );
        }
        Ok(())
    };
    valid_lanes(&selection.always)?;
    ensure!(!selection.rules.is_empty(), "empty path selection rules");
    for rule in &selection.rules {
        valid_lanes(&rule.lanes)?;
        ensure!(!rule.paths.is_empty(), "empty path selection paths");
        for pattern in &rule.paths {
            config::validate_path(pattern)?;
            ensure!(
                pattern.is_ascii()
                    && !pattern.starts_with('!')
                    && !pattern.contains(['?', '[', ']'])
                    && pattern.split('/').filter(|part| *part == "**").count() <= 1
                    && pattern
                        .split('/')
                        .all(|part| !part.contains("**") || part == "**"),
                "invalid path selection glob"
            );
        }
    }
    Ok(())
}

// Anchored component globs: * never crosses /; one ** component matches zero
// or more components. No escaping, classes, negation or locale dependencies.
fn component(pattern: &str, text: &str) -> bool {
    let (mut p, mut t, mut star, mut retry) = (0, 0, None, 0);
    let (pattern, text) = (pattern.as_bytes(), text.as_bytes());
    while t < text.len() {
        if p < pattern.len() && pattern[p] == b'*' {
            star = Some(p);
            p += 1;
            retry = t;
        } else if p < pattern.len() && pattern[p] == text[t] {
            p += 1;
            t += 1;
        } else if let Some(position) = star {
            retry += 1;
            t = retry;
            p = position + 1;
        } else {
            return false;
        }
    }
    while p < pattern.len() && pattern[p] == b'*' {
        p += 1;
    }
    p == pattern.len()
}

fn matches(pattern: &str, path: &str) -> bool {
    let mut patterns = pattern.split('/');
    let mut paths = path.split('/');
    while let Some(part) = patterns.next() {
        if part == "**" {
            let suffix = patterns.clone().count();
            let remaining = paths.clone().count();
            if remaining < suffix {
                return false;
            }
            for _ in 0..remaining - suffix {
                paths.next();
            }
        } else if !paths.next().is_some_and(|path| component(part, path)) {
            return false;
        }
    }
    paths.next().is_none()
}

pub fn select(repo: &Path, base: &str, head: &str, policy: &Policy) -> Result<Option<Selection>> {
    let Some(selection) = &policy.path_selection else {
        return Ok(None);
    };
    validate(policy)?;
    ensure!(
        config::full_commit(base) && config::full_commit(head),
        "selection requires full commit IDs"
    );
    let paths = git::git(
        repo,
        &[
            "diff",
            "--no-ext-diff",
            "--no-textconv",
            "--no-renames",
            "--raw",
            "--no-abbrev",
            "-z",
            base,
            head,
            "--",
        ],
    )?;
    let mut lanes: BTreeSet<&str> = selection.always.iter().map(String::as_str).collect();
    let mut fallback_all = false;
    let mut entries = paths.split(|byte| *byte == 0);
    while let Some(header) = entries.next().filter(|header| !header.is_empty()) {
        let header = std::str::from_utf8(header)?;
        let mut fields = header.split_ascii_whitespace();
        let old = fields.next().and_then(|mode| mode.strip_prefix(':'));
        let new = fields.next();
        if !old.is_some_and(|mode| ["000000", "100644", "100755"].contains(&mode))
            || !new.is_some_and(|mode| ["000000", "100644", "100755"].contains(&mode))
        {
            fallback_all = true;
            break;
        }
        let path = entries
            .next()
            .ok_or_else(|| anyhow::anyhow!("incomplete path diff"))?;
        let Ok(path) = std::str::from_utf8(path) else {
            fallback_all = true;
            break;
        };
        let mut covered = false;
        for rule in &selection.rules {
            if rule.paths.iter().any(|pattern| matches(pattern, path)) {
                covered = true;
                lanes.extend(rule.lanes.iter().map(String::as_str));
            }
        }
        for (name, lane) in &policy.lanes {
            if lane
                .definition_paths
                .iter()
                .chain(&lane.environment.paths)
                .chain(std::iter::once(&lane.environment.manifest))
                .any(|dependency| super::matches_path(path, dependency))
            {
                lanes.insert(name);
            }
        }
        if !covered {
            fallback_all = true;
            break;
        }
    }
    if fallback_all {
        lanes.extend(policy.lanes.keys().map(String::as_str));
    }
    Ok(Some(Selection {
        base: base.into(),
        head: head.into(),
        policy_sha256: config::hash(selection)?,
        changed_paths_sha256: config::hash(&paths)?,
        lanes: lanes.into_iter().map(str::to_owned).collect(),
        fallback_all,
    }))
}

pub fn inputs(selection: Option<&Selection>) -> Result<BTreeMap<String, String>> {
    Ok(match selection {
        Some(selection) => {
            BTreeMap::from([("lane_selection".into(), serde_json::to_string(selection)?)])
        }
        None => BTreeMap::new(),
    })
}

#[cfg(test)]
mod tests {
    use super::matches;
    #[test]
    fn globs_are_anchored_and_component_scoped() {
        for (pattern, path, expected) in [
            ("**/*.md", "README.md", true),
            ("**/*.md", "docs/a.md", true),
            ("*.md", "docs/a.md", false),
            ("docs/**", "docs/a/b", true),
            ("docs/**", "docs2/a", false),
            ("flakes/*/nix/**", "flakes/a/nix/b/c", true),
            ("flake.lock", "flake.lock.bak", false),
            ("**/*.nix", "a/b.nix", true),
            ("a*b*c", "axbyc", true),
            ("a*b*c", "axbyd", false),
        ] {
            assert_eq!(matches(pattern, path), expected, "{pattern} {path}");
        }
    }
}
