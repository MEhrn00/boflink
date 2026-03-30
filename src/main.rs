use std::{ffi::OsString, io::IsTerminal, num::NonZeroUsize, process::ExitCode};

use boflink_arena::{BumpPool, TypedArenaPool};

use boflink::{
    ErrorContext,
    cli::{CARGO_PKG_NAME, Cli, CliOptions},
    context::LinkContext,
    linker::LinkInputs,
    logging::Logger,
    stdext::time::DurationExt,
};
use indexmap::IndexSet;

/// cli entrypoint
fn main() -> ExitCode {
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
        return ExitCode::SUCCESS;
    } else if args.options.version {
        println!("{}", args.render_version());
        return ExitCode::SUCCESS;
    } else if args.options.print_gcc_specs {
        print_gcc_specs();
        return ExitCode::SUCCESS;
    }

    if args.options.color_used {
        log::warn!("'--color' is deprecated and will be removed in a future release");
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

fn try_main(mut args: Cli) -> boflink::Result<()> {
    let num_threads = args.options.threads.get_or_insert_with(|| {
        std::thread::available_parallelism().map_or_else(
            |_| NonZeroUsize::new(1).unwrap(),
            |threads| {
                // Cap the number of threads to 32 if Rust detects more than 32
                // available parallel units.
                threads.min(NonZeroUsize::new(32).unwrap())
            },
        )
    });

    let thread_pool = rayon::ThreadPoolBuilder::new()
        .num_threads(num_threads.get())
        .build()
        .context("cannot create thread pool")?;

    let print_timing = args.options.print_timing;
    let timer = std::time::Instant::now();
    thread_pool.install(|| run_boflink(args))?;

    if print_timing {
        let elapsed = std::time::Instant::now() - timer;
        log::info!("link time: {}", elapsed.display());
    }

    Ok(())
}

fn run_boflink(mut args: Cli) -> boflink::Result<()> {
    let bump_pool = BumpPool::new();
    let mapping_pool = TypedArenaPool::new();
    let obj_pool = TypedArenaPool::new();
    let inputs = std::mem::take(&mut args.inputs);
    setup_options(&mut args.options);

    let logger = create_logger(&args.options);
    let mut ctx = LinkContext::new(logger, &args.options, &bump_pool, &mapping_pool, &obj_pool);
    let mut link_inputs = LinkInputs::read_inputs(&mut ctx, &inputs)?;
    link_inputs.add_symbols(&ctx);
    let mut linker = link_inputs.resolve_symbols(&ctx);

    if ctx.options.gc_sections {
        linker.do_gc(&ctx);
    }

    linker.dedup_gcc_ident();

    if ctx.options.define_common {
        linker.define_common_symbols();
    }

    if ctx.options.stats {
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
    let library_path = std::mem::take(&mut options.library_path)
        .into_iter()
        .collect::<IndexSet<_>>();

    options.library_path = library_path.into_iter().collect();
}

fn setup_global_logging(options: &CliOptions) {
    let mut max_level = log::Level::Info;
    if options.verbose >= 2 {
        max_level = log::Level::Trace;
    } else if options.verbose >= 1 {
        max_level = log::Level::Debug;
    }

    boflink::logging::init(max_level, options.color_diagnostics, options.error_limit)
        .expect("logging should only be initialized once");
}

fn create_logger(options: &CliOptions) -> Logger {
    let mut max_level = log::Level::Info;
    if options.verbose >= 2 {
        max_level = log::Level::Trace;
    } else if options.verbose >= 1 {
        max_level = log::Level::Debug;
    }

    Logger::new(max_level, options.color_diagnostics, options.error_limit)
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
            "# Copy the text below '---' to a file named \"boflink.specs\" and run \"x86_64-w64-mingw32-gcc -specs=boflink.specs ...\"\n---"
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
