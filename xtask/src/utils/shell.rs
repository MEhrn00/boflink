use std::{ffi::OsStr, path::Path, process::Command};

use crate::utils::env::exe::cargo;

use super::env::project_root;

pub fn check_output<I: IntoIterator<Item = S>, S: AsRef<OsStr>>(
    path: impl AsRef<Path>,
    prog: impl AsRef<OsStr>,
    args: I,
) -> std::io::Result<String> {
    let output = Command::new(prog).current_dir(path).args(args).output()?;

    if !output.status.success() {
        Err(std::io::Error::other("command returned non-zero exit code"))
    } else {
        Ok(std::str::from_utf8(&output.stdout)
            .map_err(std::io::Error::other)?
            .to_string())
    }
}

pub fn check_output_projdir<I: IntoIterator<Item = S>, S: AsRef<OsStr>>(
    prog: impl AsRef<OsStr>,
    args: I,
) -> std::io::Result<String> {
    check_output(project_root()?, prog, args)
}

pub fn run_command<I: IntoIterator<Item = S>, S: AsRef<OsStr>>(
    path: impl AsRef<Path>,
    prog: impl AsRef<OsStr>,
    args: I,
) -> std::io::Result<()> {
    let status = Command::new(prog).current_dir(path).args(args).status()?;

    if !status.success() {
        Err(std::io::Error::other("command returned non-zero exit code"))
    } else {
        Ok(())
    }
}

#[allow(unused)]
pub fn run_command_projdir<I: IntoIterator<Item = S>, S: AsRef<OsStr>>(
    prog: impl AsRef<OsStr>,
    args: I,
) -> std::io::Result<()> {
    run_command(project_root()?, prog, args)
}

pub fn run_echo<I: IntoIterator<Item = S>, S: AsRef<OsStr>>(
    path: impl AsRef<Path>,
    prog: impl AsRef<OsStr>,
    args: I,
) -> std::io::Result<()> {
    let args = args.into_iter().collect::<Vec<_>>();

    let prog_exe = Path::new(prog.as_ref())
        .file_name()
        .unwrap_or_else(|| prog.as_ref());

    print!("{}", prog_exe.display());

    if !args.is_empty() {
        for arg in &args {
            print!(" {}", arg.as_ref().display());
        }
    }

    println!();
    run_command(path, prog, args)
}

pub fn run_echo_projdir<I: IntoIterator<Item = S>, S: AsRef<OsStr>>(
    prog: impl AsRef<OsStr>,
    args: I,
) -> std::io::Result<()> {
    run_echo(project_root()?, prog, args)
}

pub fn run_cargo<I: IntoIterator<Item = S>, S: AsRef<OsStr>>(args: I) -> std::io::Result<()> {
    run_echo_projdir(cargo(), args)
}
