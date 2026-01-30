use std::process::ExitCode;

use anyhow::Context;

use crate::{
    cli::{CliArgs, CliOptions},
    linker::{Config, Linker},
    timing::DurationFormatter,
};

mod api;
mod cli;
mod coff;
mod drectve;
mod fsutils;
mod graph;
mod linker;
mod linkobject;
mod logging;
mod timing;

#[cfg(windows)]
mod undname;

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

fn try_main(mut args: CliArgs) -> anyhow::Result<()> {
    let timer = std::time::Instant::now();

    let mut config = Config {
        custom_api: args
            .options
            .custom_api
            .take()
            .map(|api| api.to_string_lossy().to_string()),
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
        merge_grouped_sections: args.options.force_group_allocation,
        print_gc_sections: args.options.print_gc_sections,
        search_paths: std::mem::take(&mut args.options.library_path)
            .into_iter()
            .collect(),
        target_architecture: args.options.machine.take().map(Into::into),
        warn_unresolved: args.options.warn_unresolved_symbols,
        inputs: std::mem::take(&mut args.inputs).into_iter().collect(),
    };

    if cfg!(windows) {
        if let Some(libenv) = std::env::var_os("LIB") {
            config.search_paths.extend(std::env::split_paths(&libenv));
        }
    }

    let mut linker = Linker::new(config);
    let built = linker.link()?;
    std::fs::write(&args.options.output, built).context("cannot write output file")?;

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
