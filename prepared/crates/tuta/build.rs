use sha2::{Digest, Sha256};
use std::{fs, path::Path};

fn hash(data: &[u8]) -> String {
    format!("{:x}", Sha256::digest(data))
}

fn files(dir: &Path, root: &Path, out: &mut Vec<(String, Vec<u8>)>) -> Result<(), String> {
    let metadata = fs::symlink_metadata(dir).map_err(|e| e.to_string())?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(format!("{} is not a directory", dir.display()));
    }
    for entry in fs::read_dir(dir).map_err(|e| e.to_string())? {
        let path = entry.map_err(|e| e.to_string())?.path();
        let metadata = fs::symlink_metadata(&path).map_err(|e| e.to_string())?;
        if metadata.file_type().is_symlink() {
            return Err(format!("SDK symlink refused: {}", path.display()));
        }
        if metadata.is_dir() {
            files(&path, root, out)?;
        } else if metadata.is_file() {
            let name = path
                .strip_prefix(root)
                .unwrap()
                .to_str()
                .ok_or("Non-UTF8 SDK path")?
                .replace('\\', "/");
            out.push((name, fs::read(path).map_err(|e| e.to_string())?));
        } else {
            return Err("SDK contains a special file".into());
        }
    }
    Ok(())
}

fn verify(root: &Path) -> Result<(), String> {
    let sdk = root.join("sdk");
    let expected = fs::read_to_string(sdk.join("EXPECTED")).map_err(|e| e.to_string())?;
    let mut lines = expected.lines();
    let base = lines
        .next()
        .and_then(|s| s.strip_prefix("base="))
        .ok_or("Missing expected base")?;
    let tree = lines
        .next()
        .and_then(|s| s.strip_prefix("tree="))
        .ok_or("Missing expected tree")?;
    let content = lines
        .next()
        .and_then(|s| s.strip_prefix("content="))
        .ok_or("Missing expected content")?;
    for (value, len) in [(base, 40), (tree, 40), (content, 64)] {
        if value.len() != len
            || !value
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        {
            return Err("Invalid SDK expected digest".into());
        }
    }
    let actual_base = fs::read_to_string(sdk.join("BASE")).map_err(|e| e.to_string())?;
    let commits: Vec<_> = actual_base
        .lines()
        .filter_map(|s| s.strip_prefix("commit="))
        .collect();
    if commits != [base] {
        return Err("SDK base differs from sdk/EXPECTED".into());
    }
    for entry in fs::read_dir(sdk.join("patches")).map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        if !entry.file_type().map_err(|e| e.to_string())?.is_file() {
            return Err("SDK patches must be regular files in one directory".into());
        }
    }
    let mut patch_files = Vec::new();
    files(&sdk.join("patches"), &sdk.join("patches"), &mut patch_files)?;
    patch_files.retain(|(name, _)| name.ends_with(".patch"));
    patch_files.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
    let actual: Vec<_> = patch_files
        .iter()
        .map(|(name, data)| format!("patch={}:{}", name, hash(data)))
        .collect();
    let recorded: Vec<_> = lines.collect();
    if actual.is_empty() || actual != recorded {
        return Err("SDK patch series differs from sdk/EXPECTED".into());
    }
    let folder = sdk.join("generated");
    if !folder.exists() {
        return Err("sdk/generated is missing".into());
    }
    let mut source_files = Vec::new();
    files(&folder, &folder, &mut source_files)?;
    source_files.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
    let mut digest = Sha256::new();
    for (name, data) in source_files {
        digest.update((name.len() as u64).to_be_bytes());
        digest.update(name.as_bytes());
        digest.update((data.len() as u64).to_be_bytes());
        digest.update(data);
    }
    if format!("{:x}", digest.finalize()) != content {
        return Err("Prepared SDK content differs from sdk/EXPECTED".into());
    }
    Ok(())
}

fn main() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    for path in ["BASE", "EXPECTED", "patches", "generated"] {
        println!(
            "cargo:rerun-if-changed={}",
            root.join("sdk").join(path).display()
        );
    }
    if let Err(error) = verify(&root) {
        panic!("{error}. Run python3 scripts/sdk-prepare.py before building.");
    }
}
