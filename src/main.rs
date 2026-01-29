use std::process::Command;

use anyhow::{Result, anyhow, bail};
use log::{debug, error, info};

use arguments::{ParsedCliArgs, ParsedCliInput};
use libsearch::LibrarySearcher;
use linker::{LinkError, LinkerBuilder};

mod api;
mod arguments;
mod drectve;
mod graph;
mod libsearch;
mod linker;
mod linkobject;
mod logging;

#[cfg(windows)]
mod undname;

#[derive(Debug)]
struct EmptyError;

impl std::fmt::Display for EmptyError {
    fn fmt(&self, _f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Ok(())
    }
}

impl std::error::Error for EmptyError {}

/// cli entrypoint
fn main() {
    if let Err(e) = try_main() {
        if let Some(link_error) = e.downcast_ref::<LinkError>() {
            match link_error {
                LinkError::Setup(setup_errors) => {
                    for setup_error in setup_errors.errors() {
                        error!("{setup_error}");
                    }
                }
                LinkError::Symbol(symbol_errors) => {
                    for symbol_error in symbol_errors.errors() {
                        error!("{symbol_error}");
                    }
                }
                _ => {
                    error!("{e}");
                }
            }
        } else if !e.is::<EmptyError>() {
            error!("{e}");
        }

        std::process::exit(1);
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

    let mingwbin = if args.options.mingw64 {
        Some("x86_64-w64-mingw32-gcc")
    } else if args.options.mingw32 {
        Some("i686-w64-mingw32-gcc")
    } else if args.options.ucrt64 {
        Some("x86_64-w64-mingw32ucrt-gcc")
    } else if args.options.ucrt32 {
        Some("i686-w64-mingw32ucrt-gcc")
    } else {
        None
    };

    if let Some(mingwbin) = mingwbin {
        let query = Command::new(mingwbin)
            .arg("--print-search-dirs")
            .output()
            .map_err(|e| anyhow!("could not query {mingwbin} ({e})"))?;

        if !query.status.success() {
            if let Some(code) = query.status.code() {
                bail!("{mingwbin} returned a non-zero exit code {code}");
            } else {
                bail!("{mingwbin} exited abruptly");
            }
        }

        let stdout = std::str::from_utf8(&query.stdout)
            .map_err(|e| anyhow!("could not decode {mingwbin} output ({e})"))?;

        for line in stdout.lines() {
            if let Some(line) = line.strip_prefix("libraries: ") {
                let line = line.trim_start_matches("=");

                if log::log_enabled!(log::Level::Debug) {
                    let search_paths = std::env::split_paths(line).collect::<Vec<_>>();
                    debug!("search paths from {mingwbin}: {search_paths:?}");
                    library_searcher.extend_search_paths(search_paths);
                } else {
                    library_searcher.extend_search_paths(std::env::split_paths(line));
                }

                break;
            }
        }
    }

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

    match linker.link() {
        Ok(built) => {
            std::fs::write(&args.options.output, built)
                .map_err(|e| anyhow!("could not write output file: {e}"))?;
        }
        Err(e) => {
            return Err(anyhow!(e));
        }
    }

    Ok(())
}
