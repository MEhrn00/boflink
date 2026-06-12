use std::{ffi::OsString, io::IsTerminal, process::ExitCode};

use anyhow::{Context, Result, bail};
use log::{error, info};

use crate::{
    cli::{CARGO_PKG_NAME, Cli, CliOptions},
    linker::{Config, Linker},
    stdext::time::DurationExt,
};

mod api;
mod cli;
mod drectve;
mod graph;
mod linker;
mod linkobject;
mod logging;
mod stdext;

#[cfg(windows)]
mod undname;

/// cli entrypoint
fn main() -> ExitCode {
    if let Err(e) = try_main() {
        error!("{e:#}");
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

/// Main program entrypoint
fn try_main() -> Result<()> {
    let cmdline = Cli::expand_response_files(std::env::args_os());
    let mut args = Cli::new();
    let res = args.try_update_from(cmdline.iter().skip(1));
    setup_global_logging(&args.options);

    if args.options.verbose >= 1 {
        log::info!("{}", args.render_version());
        log_cmdline(&cmdline);
    }

    if args.options.help {
        println!("{}", args.render_help(args.options.help_ignored));
        return Ok(());
    } else if args.options.version {
        println!("{}", args.render_version());
        return Ok(());
    } else if args.options.print_gcc_specs {
        print_gcc_specs();
        return Ok(());
    }

    if args.options.color_used {
        log::warn!("'--color' is deprecated and will be removed in a future release");
    }

    if let Err(e) = res {
        bail!("{e:#}");
    }

    let it = std::time::Instant::now();

    let link_result = run_linker(&mut args);

    let elapsed = std::time::Instant::now() - it;
    if args.options.print_timing {
        info!("link time: {}", elapsed.display());
    }

    link_result
}

/// Runs the linker with the command line arguments
fn run_linker(args: &mut Cli) -> anyhow::Result<()> {
    let mut config = Config {
        custom_api: args.options.custom_api.take(),
        entrypoint: Some(std::mem::take(&mut args.options.entry)),
        gc_sections: args.options.gc_sections,
        gc_roots: std::mem::take(&mut args.options.require_defined)
            .into_iter()
            .collect(),
        ignored_unresolved_symbols: std::mem::take(&mut args.options.ignore_unresolved_symbol)
            .into_iter()
            .collect(),
        link_graph_output: args.options.dump_link_graph.take(),
        merge_bss: args.options.merge_bss,
        merge_grouped_sections: args.options.merge_groups,
        print_gc_sections: args.options.print_gc_sections,
        search_paths: std::mem::take(&mut args.options.library_path)
            .into_iter()
            .collect(),
        target_architecture: args.options.machine.take().map(Into::into),
        warn_unresolved: args.options.warn_unresolved_symbols,
        inputs: std::mem::take(&mut args.inputs).into_iter().collect(),
    };

    if cfg!(windows)
        && let Some(libenv) = std::env::var_os("LIB")
    {
        config.search_paths.extend(std::env::split_paths(&libenv));
    }

    let mut linker = Linker::new(config);
    let built = linker.link()?;
    std::fs::write(&args.options.output, built).context("cannot write output file")?;
    Ok(())
}

fn setup_global_logging(options: &CliOptions) {
    let mut max_level = log::Level::Info;
    if options.verbose >= 2 {
        max_level = log::Level::Trace;
    } else if options.verbose >= 1 {
        max_level = log::Level::Debug;
    }

    crate::logging::init(max_level, options.color_diagnostics, options.error_limit)
        .expect("logging should only be initialized once");
}

fn log_cmdline(args: &[OsString]) {
    let args = args.iter().map(|s| s.to_string_lossy()).collect::<Vec<_>>();
    log::info!("command line: {}", args.join(" "));
}

fn print_gcc_specs() {
    // Print out a header with instructions only if printing to a terminal.
    // Just print out the raw spec file content if the output is potentially being redirected to a
    // file.
    if std::io::stdout().is_terminal() {
        println!(
            "# Copy the text below the '---' line to a file named \"boflink.specs\" and run \"x86_64-w64-mingw32-gcc -specs=boflink.specs ...\"\n---"
        );
    }

    let current_exe = std::env::current_exe()
        .map(|exe| exe.into_os_string())
        .unwrap_or_else(|_| OsString::from(CARGO_PKG_NAME));

    println!(
        "*linker:\n\
        {current_exe}",
        current_exe = current_exe.display()
    );
}
