use std::{
    path::PathBuf,
    process::{Command, ExitCode},
};

use anyhow::{Context, Result, bail};
use log::{error, info};

use arguments::{ParsedCliArgs, ParsedCliInput};

use crate::{
    arguments::CliOptionArgs,
    linker::{Config, LinkInput, LinkInputOptions, LinkInputVariant, Linker},
};

mod api;
mod arguments;
mod drectve;
mod fsutils;
mod graph;
mod linker;
mod linkobject;
mod logging;

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
    let mut args = arguments::parse_arguments()?;

    let it = std::time::Instant::now();

    let link_result = run_linker(&mut args);

    let elapsed = std::time::Instant::now() - it;
    if args.options.print_timing {
        info!("link time: {}ms", elapsed.as_micros() as f64 / 1000f64);
    }

    link_result
}

/// Runs the linker with the command line arguments
fn run_linker(args: &mut ParsedCliArgs) -> anyhow::Result<()> {
    let mut config = Config {
        custom_api: args.options.custom_api.take(),
        entrypoint: Some(std::mem::take(&mut args.options.entry)),
        gc_sections: args.options.gc_sections,
        gc_roots: std::mem::take(&mut args.options.keep_symbol)
            .into_iter()
            .collect(),
        ignored_unresolved_symbols: std::mem::take(&mut args.options.ignore_unresolved_symbol)
            .into_iter()
            .collect(),
        link_graph_output: args.options.dump_link_graph.take(),
        merge_bss: args.options.merge_bss,
        merge_grouped_sections: args.options.merge_groups,
        print_gc_sections: args.options.print_gc_sections,
        search_paths: std::mem::take(&mut args.options.library_paths)
            .into_iter()
            .collect(),
        target_architecture: args.options.machine.take().map(Into::into),
        warn_unresolved: args.options.warn_unresolved_symbols,
        ..Default::default()
    };

    if cfg!(windows) {
        if let Some(libenv) = std::env::var_os("LIB") {
            config.search_paths.extend(std::env::split_paths(&libenv));
        }
    }

    config
        .search_paths
        .extend(include_mingw_search_paths(&args.options)?);

    let mut whole = false;
    for input in std::mem::take(&mut args.inputs) {
        match input {
            ParsedCliInput::WholeArchiveStart => {
                whole = true;
            }
            ParsedCliInput::WholeArchiveEnd => {
                whole = false;
            }
            ParsedCliInput::File(file_path) => {
                config.inputs.insert(LinkInput {
                    variant: LinkInputVariant::File(file_path),
                    options: LinkInputOptions { whole },
                });
            }
            ParsedCliInput::Library(library) => {
                config.inputs.insert(LinkInput {
                    variant: LinkInputVariant::Library(library),
                    options: LinkInputOptions { whole },
                });
            }
        }
    }

    let mut linker = Linker::new(config);
    let built = linker.link()?;
    std::fs::write(&args.options.output, built).context("cannot write output file")?;
    Ok(())
}

fn include_mingw_search_paths(options: &CliOptionArgs) -> anyhow::Result<Vec<PathBuf>> {
    let mut search_paths = Vec::new();
    if options.mingw64 {
        search_paths = query_gcc("x86_64-w64-mingw32-gcc")?;
    } else if options.mingw32 {
        search_paths = query_gcc("i686-w64-mingw32-gcc")?;
    } else if options.ucrt64 {
        search_paths = query_gcc("x86_64-w64-mingw32ucrt-gcc")?;
    } else if options.ucrt32 {
        search_paths = query_gcc("i686-w64-mingw32ucrt-gcc")?;
    }

    Ok(search_paths)
}

/// Queries the specified MinGW GCC executable for its list of library search
/// paths.
fn query_gcc(gcc: &str) -> anyhow::Result<Vec<PathBuf>> {
    let cmdline = || format!("{gcc} --print-search-dirs");

    let print_search_dirs = Command::new(gcc)
        .arg("--print-search-dirs")
        .output()
        .with_context(|| format!("cannot run '{}'", cmdline()))?;

    if !print_search_dirs.status.success() {
        if let Some(code) = print_search_dirs.status.code() {
            bail!("'{}' returned a non-zero exit code {code}", cmdline());
        } else {
            bail!("'{}' exited abruptly", cmdline());
        }
    }

    let stdout = std::str::from_utf8(&print_search_dirs.stdout)
        .with_context(|| format!("cannot decode '{}' output", cmdline()))?;

    let libraries = stdout.lines().find_map(|line| {
        let line = line.strip_prefix("libraries: ")?;
        Some(line.trim_start_matches("="))
    });

    let search_dirs = Vec::from_iter(libraries.into_iter().flat_map(|libraries| {
        std::env::split_paths(libraries).map(fsutils::lexically_normalize_path)
    }));

    Ok(search_dirs)
}
