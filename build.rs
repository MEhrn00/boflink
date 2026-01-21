fn emit_githash() -> std::io::Result<()> {
    let git_head = std::fs::read_to_string(".git/HEAD")?.trim().to_string();
    println!("cargo::rerun-if-changed=.git/HEAD");

    let githash = if let Some(head_ref) = git_head.strip_prefix("ref: ") {
        let head_ref = format!(".git/{head_ref}");
        let githash = std::fs::read_to_string(&head_ref)?;
        println!("cargo::rerun-if-changed={head_ref}");
        githash
    } else {
        git_head
    };

    let hashval = githash.trim();
    let shorthash = if hashval.len() == 40 {
        &hashval[..7]
    } else {
        "unknown"
    };
    println!("cargo::rustc-env=GIT_SHORT_HASH={shorthash}");

    Ok(())
}

fn main() {
    println!("cargo::rerun-if-changed=build.rs");
    if emit_githash().is_err() {
        println!("cargo::rustc-env=GIT_SHORT_HASH=unknown")
    }
}
