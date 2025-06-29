use std::process::Command;

fn emit_githash() -> std::io::Result<()> {
    let git_version = Command::new("git").arg("--version").spawn()?.wait()?;

    if !git_version.success() {
        return Err(std::io::Error::other("git --version exited unsuccessfully"));
    }

    let git_head = std::fs::read_to_string(".git/HEAD")?;

    let git_ref = git_head
        .split_once(" ")
        .map(|(_, head_ref)| head_ref)
        .ok_or_else(|| std::io::Error::other("could not get git HEAD ref"))?;

    let git_shorthash_output = Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()?;

    let shorthash = std::str::from_utf8(git_shorthash_output.stdout.as_slice())
        .map_err(std::io::Error::other)?;

    println!("cargo::rustc-env=GIT_SHORT_HASH={shorthash}");
    println!("cargo::rerun-if-changed=.git/HEAD");
    println!("cargo::rerun-if-changed=.git/{git_ref}");

    Ok(())
}

fn main() {
    println!("cargo::rerun-if-changed=build.rs");
    if emit_githash().is_err() {
        println!("cargo::rustc-env=GIT_SHORT_HASH=unknown");
    }
}
