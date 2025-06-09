use anyhow::{Result, anyhow, bail};
use arguments::CliArgs;
use log::{error, info};

use boflink::{
    libsearch::LibrarySearcher,
    linker::{LinkerBuilder, error::LinkError},
    pathed_item::PathedItem,
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

    let link_res = run_linker(&mut args);

    let elapsed = std::time::Instant::now() - it;
    if args.print_timing {
        info!("link time: {}ms", elapsed.as_micros() as f64 / 1000f64);
    }

    link_res
}

fn run_linker(args: &mut CliArgs) -> anyhow::Result<()> {
    let mut library_searcher = LibrarySearcher::new();
    library_searcher.extend_search_paths(std::mem::take(&mut args.library_paths));

    if cfg!(windows) {
        if let Some(libenv) = std::env::var_os("LIB") {
            library_searcher.extend_search_paths(std::env::split_paths(&libenv));
        }
    }

    let linker = LinkerBuilder::new()
        .library_searcher(library_searcher)
        .entrypoint(std::mem::take(&mut args.entry))
        .add_libraries(std::mem::take(&mut args.libraries))
        .merge_bss(args.merge_bss)
        .gc_sections(args.gc_sections)
        .print_gc_sections(args.print_gc_sections)
        .add_gc_keep_symbols(std::mem::take(&mut args.keep_symbol));

    let linker = if let Some(target_arch) = args.machine.take() {
        linker.architecture(target_arch.into())
    } else {
        linker
    };

    let linker = if let Some(graph_path) = args.dump_link_graph.take() {
        linker.link_graph_path(graph_path)
    } else {
        linker
    };

    let linker = if let Some(custom_api) = args.custom_api.take() {
        linker.custom_api(custom_api)
    } else {
        linker
    };

    let mut error_flag = false;
    let inputs = std::mem::take(&mut args.files)
        .into_iter()
        .filter_map(|file| match std::fs::read(&file) {
            Ok(buffer) => Some(PathedItem::new(file, buffer)),
            Err(e) => {
                error!("could not open {}: {e}", file.display());
                error_flag = true;
                None
            }
        })
        .collect::<Vec<_>>();

    let linker = linker.add_inputs(inputs);

    if error_flag {
        bail!(EmptyError);
    }

    let mut linker = linker.build();

    match linker.link() {
        Ok(built) => {
            std::fs::write(&args.output, built)
                .map_err(|e| anyhow!("could not write output file: {e}"))?;
        }
        Err(e) => {
            return Err(anyhow!(e));
        }
    }

    Ok(())
}
