//! Measure registered Nix closures without evaluating consumer expressions.
use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, path::Path, process::Command};

fn closure(bytes: &[u8], root: &str) -> Result<BTreeMap<String, String>> {
    let value: serde_json::Value = serde_json::from_slice(bytes)?;
    let mut paths = BTreeMap::new();
    let mut insert = |path: &str, info: &serde_json::Value| -> Result<()> {
        ensure!(
            crate::gate::config::nix_store_path(path),
            "invalid closure path"
        );
        let hash = info
            .get("narHash")
            .and_then(serde_json::Value::as_str)
            .context("missing closure narHash")?;
        ensure!(
            hash.strip_prefix("sha256-")
                .and_then(|h| STANDARD.decode(h).ok())
                .is_some_and(|h| h.len() == 32),
            "invalid closure narHash"
        );
        ensure!(
            paths.insert(path.to_owned(), hash.to_owned()).is_none(),
            "duplicate closure path"
        );
        Ok(())
    };
    if let Some(entries) = value.as_object() {
        for (path, info) in entries {
            insert(path, info)?;
        }
    } else if let Some(entries) = value.as_array() {
        for info in entries {
            insert(
                info.get("path")
                    .and_then(serde_json::Value::as_str)
                    .context("missing closure path")?,
                info,
            )?;
        }
    } else {
        anyhow::bail!("invalid Nix path-info response");
    }
    ensure!(paths.contains_key(root), "Nix closure omits requested root");
    Ok(paths)
}

pub fn measure(nix: &Path, root: &str) -> Result<BTreeMap<String, String>> {
    ensure!(
        crate::gate::config::nix_store_path(root),
        "invalid Nix store root"
    );
    ensure!(
        std::fs::canonicalize(root)? == Path::new(root),
        "Nix artifact must be its registered store root"
    );
    let output = Command::new(nix)
        .env_clear()
        .env("LC_ALL", "C")
        .args([
            "--extra-experimental-features",
            "nix-command",
            "path-info",
            "--recursive",
            "--json",
            "--",
            root,
        ])
        .output()
        .context("measuring Nix closure")?;
    ensure!(
        output.status.success(),
        "Nix artifact is missing or invalid: {root}"
    );
    let paths = closure(&output.stdout, root)?;
    for path in paths.keys() {
        ensure!(Path::new(path).exists(), "missing Nix closure member");
    }
    Ok(paths)
}

pub fn digest(paths: &BTreeMap<String, String>) -> Result<String> {
    // Compact JSON sorted [path,narHash] tuples, not Nix's incidental output order.
    Ok(hex::encode(Sha256::digest(serde_json::to_vec(
        &paths.iter().collect::<Vec<_>>(),
    )?)))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn closure_order_and_formats_are_irrelevant() {
        let a = "/nix/store/00000000000000000000000000000000-a";
        let b = "/nix/store/11111111111111111111111111111111-b";
        let hash = format!("sha256-{}", STANDARD.encode([0; 32]));
        let array = serde_json::json!([{"path":b,"narHash":hash},{"path":a,"narHash":hash}]);
        let object = serde_json::json!({a:{"narHash":hash},b:{"narHash":hash}});
        let parsed = closure(&serde_json::to_vec(&array).unwrap(), a).unwrap();
        assert_eq!(
            digest(&parsed).unwrap(),
            digest(&closure(&serde_json::to_vec(&object).unwrap(), a).unwrap()).unwrap()
        );
        assert!(closure(b"{}", a).is_err());
        assert!(
            closure(
                &serde_json::to_vec(&serde_json::json!({a:{"narHash":"bad"}})).unwrap(),
                a
            )
            .is_err()
        );
        let changed =
            BTreeMap::from([(a.to_owned(), format!("sha256-{}", STANDARD.encode([1; 32])))]);
        assert_ne!(digest(&parsed).unwrap(), digest(&changed).unwrap());
    }
}
