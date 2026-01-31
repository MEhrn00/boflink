use std::{path::PathBuf, process::ExitCode};

use indexmap::IndexSet;

use crate::{
    cli::{CliArgs, CliOptions, Emulation},
    coff::ImageFileMachine,
    context::{LinkConfig, LinkContext},
    syncpool::SyncBumpPool,
    timing::DurationFormatter,
};

mod cli;
mod coff;
mod context;
mod error;
mod fsutils;
mod inputs;
mod linker;
mod logging;
mod syncpool;
mod timing;

#[cfg(windows)]
mod undname;

pub use error::*;

/// cli entrypoint
fn main() -> ExitCode {
    let mut args = CliArgs::default();
    let cmdline = cli::expand_response_files(std::env::args_os());
    let res = args.try_update_from(cmdline.iter().skip(1));
    setup_logging(&args.options);

    if args.options.verbose >= 1 {
        cli::log_cmdline(&cmdline);
    }

    if args.options.help {
        cli::print_help(args.options.help_ignored);
        return ExitCode::SUCCESS;
    } else if args.options.version {
        cli::print_version();
        return ExitCode::SUCCESS;
    }

    if args.options.color_used {
        log::warn!("'--color' is deprecated and will be removed in the next release");
    }

    if let Err(e) = res {
        log::error!("{e:#}");
        return ExitCode::FAILURE;
    }

    if let Err(e) = try_main(args) {
        log::error!("{e:#}");
        return ExitCode::FAILURE;
    }

    ExitCode::SUCCESS
}

fn try_main(args: CliArgs) -> Result<()> {
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(
            args.options
                .threads
                .or_else(|| std::thread::available_parallelism().ok())
                .map(|num| num.get())
                .unwrap_or(1),
        )
        .build()
        .context("cannot create thread pool")?;

    pool.install(|| run_boflink(args))
}

fn run_boflink(mut args: CliArgs) -> Result<()> {
    let timer = std::time::Instant::now();

    let bump_pool = SyncBumpPool::new();

    // Deduplicate library paths
    let mut library_path: IndexSet<PathBuf> =
        IndexSet::from_iter(std::mem::take(&mut args.options.library_path).into_iter());

    // Add Windows `LIB` paths
    if cfg!(windows)
        && args.options.sysroot.is_none()
        && let Some(libenv) = std::env::var_os("LIB")
    {
        library_path.extend(
            std::env::split_paths(&libenv).map(|path| fsutils::lexically_normalize_path(path)),
        );
    }

    let ctx = LinkContext::new(
        LinkConfig {
            architecture: args
                .options
                .machine
                .map(|m| match m {
                    Emulation::I386Pep => ImageFileMachine::Amd64,
                    Emulation::I386Pe => ImageFileMachine::I386,
                })
                .unwrap_or(ImageFileMachine::Unknown),
            demangle: args.options.demangle,
            do_gc: args.options.gc_sections,
            print_gc_sections: args.options.print_gc_sections,
            error_limit: args.options.error_limit,
            strip_debug: args.options.strip_debug,
            search_paths: library_path.into_iter().collect::<Vec<_>>(),
        },
        &bump_pool,
    );

    if args.options.print_timing {
        let elapsed = std::time::Instant::now() - timer;
        log::info!("link time: {}", DurationFormatter::new(&elapsed));
    }

    Ok(())
}

fn setup_logging(options: &CliOptions) {
    let mut max_level = log::Level::Info;
    if options.verbose >= 2 {
        max_level = log::Level::Trace;
    } else if options.verbose >= 1 {
        max_level = log::Level::Debug;
    }

    crate::logging::init(max_level, options.color_diagnostics, options.error_limit)
        .expect("logging should only be initialized once");
}
