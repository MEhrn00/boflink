use anyhow::{Result, anyhow};
use arguments::{ParsedCliArgs, ParsedCliInput};
use log::{error, info};

use boflink::{
    libsearch::LibrarySearcher,
    linker::{LinkerBuilder, error::LinkError},
};

mod arguments;
mod logging;

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
                    let error_count = symbol_errors.errors().len();
                    let mut error_iter = symbol_errors.errors().iter();
                    for symbol_error in error_iter.by_ref().take(error_count.saturating_sub(1)) {
                        error!("{symbol_error}\n");
                    }

                    if let Some(last_error) = error_iter.next() {
                        error!("{last_error}");
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

    let linker = LinkerBuilder::new()
        .library_searcher(library_searcher)
        .entrypoint(std::mem::take(&mut args.options.entry))
        .merge_bss(args.options.merge_bss)
        .gc_sections(args.options.gc_sections)
        .print_gc_sections(args.options.print_gc_sections)
        .add_gc_keep_symbols(std::mem::take(&mut args.options.keep_symbol))
        .merge_grouped_sections(args.options.merge_groups);

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
