use std::{error::Error, ffi::OsString};

use crate::utils;

pub struct Task {
    pub name: &'static str,
    pub help: &'static str,
    pub run: fn() -> Result<(), Box<dyn Error>>,
}

pub const TASKLIST: &[Task] = &[
    Task {
        name: "install",
        help: "Install boflink",
        run: install,
    },
    Task {
        name: "uninstall",
        help: "Uninstall boflink",
        run: uninstall,
    },
    Task {
        name: "lint",
        help: "Lint with clippy",
        run: lint,
    },
    Task {
        name: "test",
        help: "Run tests",
        run: test,
    },
    Task {
        name: "checkfmt",
        help: "Check formatting",
        run: checkfmt,
    },
    Task {
        name: "ci",
        help: "Run ci workflow",
        run: ci,
    },
    Task {
        name: "docs",
        help: "Build documentation (requires pandoc executable)",
        run: docs,
    },
    #[cfg(feature = "dist")]
    Task {
        name: "dist",
        help: "Build a binary release dist archive",
        run: dist,
    },
    Task {
        name: "list",
        help: "List tasks",
        run: print_help,
    },
    Task {
        name: "help",
        help: "Print help",
        run: print_help,
    },
];

pub fn install() -> Result<(), Box<dyn Error>> {
    utils::shell::run_cargo(
        ["install", "--path", ".", "--bin", "boflink"]
            .into_iter()
            .map(OsString::from)
            .chain(std::env::args_os().skip(2)),
    )?;

    if cfg!(unix) {
        let exe_install_path = utils::env::cargo_home()?.join("bin").join("boflink");

        let libexec = utils::env::install_libexec().join("boflink");
        println!("mkdir -p {}", libexec.display());
        std::fs::create_dir_all(&libexec)?;

        let ldsymlink = libexec.join("ld");
        println!(
            "ln -sf {} {}",
            exe_install_path.display(),
            ldsymlink.display()
        );

        let _ = std::fs::remove_file(&ldsymlink);

        #[cfg(unix)]
        std::os::unix::fs::symlink(exe_install_path, ldsymlink)?;
    }

    Ok(())
}

pub fn uninstall() -> Result<(), Box<dyn Error>> {
    let _ = utils::shell::run_cargo(["uninstall", "boflink"]);

    if cfg!(unix) {
        let libexec = utils::env::install_libexec().join("boflink");

        let symlink = libexec.join("ld");
        println!("rm -f {}", symlink.display());
        let _ = std::fs::remove_file(symlink);

        println!("rmdir {}", libexec.display());
        let _ = std::fs::remove_dir(libexec);
    }

    Ok(())
}

pub fn lint() -> Result<(), Box<dyn Error>> {
    utils::shell::run_cargo([
        "clippy",
        "--workspace",
        "--all-features",
        "--all-targets",
        "--",
        "-D",
        "warnings",
    ])?;
    Ok(())
}

pub fn test() -> Result<(), Box<dyn Error>> {
    utils::shell::run_cargo(["test", "--workspace"])?;
    Ok(())
}

pub fn checkfmt() -> Result<(), Box<dyn Error>> {
    utils::shell::run_cargo(["fmt", "--all", "--check"])?;
    Ok(())
}

pub fn ci() -> Result<(), Box<dyn Error>> {
    checkfmt()?;
    lint()?;
    test()?;
    Ok(())
}

pub fn docs() -> Result<(), Box<dyn Error>> {
    Ok(utils::shell::run_echo_projdir(
        "pandoc",
        [
            "docs/boflink.1.md",
            "-s",
            "-t",
            "man",
            "-o",
            "docs/boflink.1",
        ],
    )?)
}

#[cfg(feature = "dist")]
pub fn dist() -> Result<(), Box<dyn Error>> {
    crate::dist::task::dist()
}

pub fn print_help() -> Result<(), Box<dyn Error>> {
    let descwidth = TASKLIST
        .iter()
        .max_by_key(|task| task.name.len())
        .map(|task| task.name.len())
        .unwrap_or_default()
        + 2;

    println!("tasks:");

    for task in TASKLIST {
        println!(" {: <descwidth$}{}", task.name, task.help);
    }

    Ok(())
}
