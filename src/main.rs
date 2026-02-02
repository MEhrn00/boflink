use std::{
    collections::HashSet, num::NonZeroUsize, path::Path, process::ExitCode, sync::atomic::Ordering,
};

use typed_arena::Arena;

use crate::{
    cli::{CliArgs, CliOptions},
    coff::ImageFileMachine,
    context::LinkContext,
    linker::Linker,
    syncpool::SyncBumpPool,
    timing::DurationExt,
};

mod cli;
mod coff;
mod context;
mod error;
mod fsutils;
mod inputs;
mod linker;
mod logging;
mod symbols;
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

fn try_main(mut args: CliArgs) -> Result<()> {
    let threads = args.options.threads.get_or_insert_with(|| {
        std::thread::available_parallelism()
            .ok()
            .unwrap_or(NonZeroUsize::new(1).unwrap_or_else(|| unreachable!()))
    });

    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(threads.get())
        .build()
        .context("cannot create thread pool")?;

    pool.install(|| run_boflink(args))
}

fn run_boflink(mut args: CliArgs) -> Result<()> {
    let timer = std::time::Instant::now();
    let bump_pool = SyncBumpPool::new();
    let mappings = Arena::new();
    let inputs = std::mem::take(&mut args.inputs);

    setup_options(&mut args.options);

    let ctx = LinkContext::new(&args.options, &bump_pool);

    let linker = Linker::read_inputs(&ctx, &inputs, &mappings)?;

    if linker.objs.is_empty() {
        bail!("no input files");
    }

    if linker.architecture == ImageFileMachine::Unknown {
        bail!("unable to detect target architecture from input files");
    }

    ctx.stats
        .global_symbols
        .store(ctx.symbol_map.len(), Ordering::Relaxed);

    if args.options.print_timing {
        let elapsed = std::time::Instant::now() - timer;
        log::info!("link time: {}", elapsed.display());
    }

    if args.options.print_stats {
        ctx.stats.print_yaml();
    }

    Ok(())
}

fn setup_options(options: &mut CliOptions) {
    if cfg!(windows)
        && options.sysroot.is_none()
        && let Some(libenv) = std::env::var_os("LIB")
    {
        options.library_path.extend(std::env::split_paths(&libenv));
    }

    dedup_library_paths(options);
}

fn dedup_library_paths(options: &mut CliOptions) {
    let arena = Arena::<u8>::new();
    let mut seen = HashSet::<&[u8]>::with_capacity(options.library_path.len());

    let save =
        |path: &Path| arena.alloc_extend(path.as_os_str().as_encoded_bytes().iter().copied());

    options
        .library_path
        .retain(|path| seen.insert(save(path.as_path())));
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
