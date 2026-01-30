use std::{
    path::PathBuf,
    process::{Command, ExitCode},
};

use anyhow::{Context, Result, bail};
use log::{error, info};

use arguments::{ParsedCliArgs, ParsedCliInput};
use libsearch::LibrarySearcher;
use linker::LinkerBuilder;

use crate::arguments::CliOptionArgs;

mod api;
mod arguments;
mod drectve;
mod fsutils;
mod graph;
mod libsearch;
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
    let mut library_searcher = LibrarySearcher::new();
    library_searcher.extend_search_paths(std::mem::take(&mut args.options.library_paths));

    if cfg!(windows) {
        if let Some(libenv) = std::env::var_os("LIB") {
            library_searcher.extend_search_paths(std::env::split_paths(&libenv));
        }
    }

    library_searcher.extend_search_paths(include_mingw_search_paths(&args.options)?);

    let mut linker = LinkerBuilder::new()
        .library_searcher(library_searcher)
        .entrypoint(std::mem::take(&mut args.options.entry))
        .merge_bss(args.options.merge_bss)
        .gc_sections(args.options.gc_sections)
        .print_gc_sections(args.options.print_gc_sections)
        .add_gc_keep_symbols(std::mem::take(&mut args.options.keep_symbol))
        .merge_grouped_sections(args.options.merge_groups)
        .warn_unresolved(args.options.warn_unresolved_symbols);

    linker
        .add_ignored_unresolved_symbols(std::mem::take(&mut args.options.ignore_unresolved_symbol));

    let linker = if let Some(target_arch) = args.options.machine.take() {
        linker.architecture(target_arch.into())
    } else {
        linker
    };

    let linker = if let Some(graph_path) = args.options.dump_link_graph.take() {
        linker.link_graph_path(graph_path)
    } else {
        linker
    };

    let mut linker = if let Some(custom_api) = args.options.custom_api.take() {
        linker.custom_api(custom_api)
    } else {
        linker
    };

    let mut whole_input = false;
    for input in std::mem::take(&mut args.inputs) {
        match input {
            ParsedCliInput::WholeArchiveStart => {
                whole_input = true;
            }
            ParsedCliInput::WholeArchiveEnd => {
                whole_input = false;
            }
            ParsedCliInput::File(file_path) => {
                if whole_input {
                    linker.add_whole_file_path(file_path);
                } else {
                    linker.add_file_path(file_path);
                }
            }
            ParsedCliInput::Library(library) => {
                if whole_input {
                    linker.add_whole_library(library);
                } else {
                    linker.add_library(library);
                }
            }
        }
    }

    let mut linker = linker.build();
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
