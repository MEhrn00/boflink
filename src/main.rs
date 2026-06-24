use std::{
    borrow::Cow,
    collections::{HashSet, VecDeque},
    ffi::OsString,
    io::{BufWriter, IsTerminal},
    path::{Path, PathBuf},
    process::ExitCode,
};

use anyhow::{Context, Result, bail};
use boflink_stdext::{path::PathExt, time::DurationExt};
use bstr::ByteSlice;
use bumpalo::Bump;
use indexmap::IndexSet;
use log::{error, info};
use object::Object;
use typed_arena::Arena;

use crate::{
    api::ApiSymbols,
    cli::{CARGO_PKG_NAME, Cli, CliOptions},
    directives::{LinkerDirective, parse_linker_directives},
    linker::{LinkInputProcessor, LinkerTargetArch, find_library},
    linkobject::archive::{LinkArchive, LinkArchiveMemberVariant},
};

mod api;
mod cli;
mod directives;
mod graph;
mod linker;
mod linkobject;

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

    args.emit_warnings();

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
    include_libenv_search_paths(args);

    let input_args = std::mem::take(&mut args.inputs);

    // Arenas
    let buffer_arena = Arena::<(PathBuf, Vec<u8>)>::with_capacity(input_args.len());
    let bump = Bump::new();

    let mut input_processor = LinkInputProcessor::with_capacity(
        &buffer_arena,
        &args.options.library_path,
        input_args.len(),
    );

    let mut errored = false;

    // Process the input files
    for link_input in input_args {
        if let Err(e) = input_processor.process_input(link_input) {
            log::error!("{e:#}");
            errored = true;
        }
    }

    input_processor.ensure_entrypoint(&args.options.entry);

    if errored {
        std::process::exit(1);
    }

    if input_processor.coffs.is_empty() {
        bail!("no input files");
    }

    let target_arch = args
        .options
        .machine
        .take()
        .map(|m| m.into())
        .or_else(|| {
            input_processor
                .coffs
                .values()
                .find_map(|coff| LinkerTargetArch::try_from(coff.architecture()).ok())
        })
        .context("cannot detect target architecture from input files")?;

    let api_symbols = args
        .options
        .custom_api
        .take()
        .map(|api| input_processor.open_custom_api(api.to_string_lossy().to_string()))
        .unwrap_or_else(|| Ok(ApiSymbols::beacon(&bump, target_arch)))?;

    // Build the graph
    let graph_arena = input_processor.alloc_arena();
    let mut graph = input_processor.alloc_graph(&graph_arena, target_arch);

    // Add COFFs
    for (coff_path, coff) in &input_processor.coffs {
        match parse_linker_directives(&bump, coff) {
            Ok(directives) => {
                for directive in directives {
                    let LinkerDirective::Defaultlib(library_name) = directive else {
                        continue;
                    };
                    let library_name = library_name.to_str_lossy();
                    if input_processor
                        .opened_library_names
                        .contains(library_name.as_ref())
                    {
                        continue;
                    }

                    let search_result = find_library(&args.options.library_path, &library_name)
                        .with_context(|| {
                            format!("{coff_path}: unable to find library {library_name}")
                        });

                    let (library_path, buffer) = match search_result {
                        Ok(v) => v,
                        Err(e) => {
                            log::error!("{e}");
                            errored = true;
                            continue;
                        }
                    };

                    input_processor
                        .opened_library_names
                        .insert(library_name.to_string());

                    if input_processor
                        .link_libraries
                        .contains_key(library_path.as_path())
                    {
                        continue;
                    }

                    let (library_path, library_buffer) = buffer_arena.alloc((library_path, buffer));
                    let archive = match LinkArchive::parse(library_buffer.as_slice()) {
                        Ok(parsed) => parsed,
                        Err(e) => {
                            log::error!("{}: {e}", library_path.as_path().display());
                            errored = true;
                            continue;
                        }
                    };

                    input_processor
                        .link_libraries
                        .insert(library_path.as_path(), archive);
                }
            }
            Err(e) => {
                log::error!("{coff_path}: {e}");
                errored = true;
            }
        }

        if let Err(e) = graph.add_coff(coff_path.file_path, coff_path.member_path, coff) {
            log::error!("{coff_path}: {e}");
            errored = true;
        }
    }

    // Check for any errors
    if errored {
        std::process::exit(1);
    }

    let mut drectve_queue = VecDeque::<((&Path, &Path), Cow<str>)>::new();

    let resolve_count = graph.archive_resolvable_externals().count();
    let mut symbol_search_buffer = VecDeque::with_capacity(resolve_count);
    let mut undefined_symbols = IndexSet::<&str>::with_capacity(resolve_count);

    // Resolve symbols
    loop {
        // Get the list of undefined symbols to search for
        symbol_search_buffer.extend(
            graph
                .archive_resolvable_externals()
                .filter(|symbol| !undefined_symbols.contains(symbol)),
        );

        // If the search list is empty, finished resolving
        if symbol_search_buffer.is_empty() {
            break;
        }

        // Attempt to resolve each symbol in the search list
        'symbol: while let Some(symbol_name) = symbol_search_buffer.pop_front() {
            // Try resolving it as an API import first
            if let Some(api_import) = api_symbols.get(symbol_name) {
                if let Err(e) = graph.add_api_import(symbol_name, api_import) {
                    log::error!("{}: {e}", api_symbols.archive_path().display());
                    errored = true;
                }

                continue;
            }

            // Open any pending libraries in the .drectve queue
            while let Some(((library_path, coff_path), drectve_library)) = drectve_queue.pop_front()
            {
                match find_library(&args.options.library_path, &drectve_library) {
                    Some(found) => {
                        if !input_processor
                            .opened_library_names
                            .contains(drectve_library.as_ref())
                        {
                            input_processor
                                .opened_library_names
                                .insert(drectve_library.to_string());

                            let (library_path, library_buffer) = buffer_arena.alloc(found);

                            match LinkArchive::parse(library_buffer.as_slice()) {
                                Ok(parsed) => {
                                    input_processor
                                        .link_libraries
                                        .insert(library_path.as_path(), parsed);
                                }
                                Err(e) => {
                                    log::error!(
                                        "{}({}): {e}",
                                        library_path.display(),
                                        coff_path.display()
                                    );
                                    errored = true;
                                }
                            }
                        }
                    }
                    None => {
                        log::error!(
                            "{}({}): unable to find library {drectve_library}",
                            library_path.display(),
                            coff_path.display()
                        );
                        errored = true;
                    }
                }
            }

            // Attempt to resolve the symbol using the opened link libraries
            for (library_path, library) in &input_processor.link_libraries {
                let (member_path, member) = match library.extract_symbol(symbol_name) {
                    Ok(Some(extracted)) => extracted,
                    Ok(None) => {
                        continue;
                    }
                    Err(e) => {
                        log::error!("{}: {e}", library_path.display());
                        errored = true;
                        continue;
                    }
                };

                match member {
                    LinkArchiveMemberVariant::Coff(coff) => {
                        // Add any .drectve link libraries from linked in COFFs
                        // to the drectve queue
                        match parse_linker_directives(&bump, &coff) {
                            Ok(directives) => {
                                for directive in directives {
                                    let LinkerDirective::Defaultlib(library_name) = directive
                                    else {
                                        continue;
                                    };
                                    let name_str = library_name.to_str_lossy();
                                    if !input_processor
                                        .opened_library_names
                                        .contains(name_str.as_ref())
                                    {
                                        drectve_queue
                                            .push_back(((library_path, member_path), name_str));
                                    }
                                }
                            }
                            Err(e) => {
                                log::error!(
                                    "{}({}): {e}",
                                    library_path.display(),
                                    member_path.display()
                                );
                                errored = true;
                            }
                        }

                        if let Err(e) = graph.add_coff(library_path, Some(member_path), &coff) {
                            log::error!(
                                "{}({}): {e}",
                                library_path.display(),
                                member_path.display()
                            );
                            errored = true;
                            continue;
                        }

                        continue 'symbol;
                    }
                    LinkArchiveMemberVariant::Import(import_member) => {
                        if let Err(e) = graph.add_library_import(symbol_name, &import_member) {
                            log::error!(
                                "{}({}): {e}",
                                library_path.display(),
                                member_path.display()
                            );
                            errored = true;
                            continue;
                        }

                        continue 'symbol;
                    }
                }
            }

            // Symbol could not be found in any of the link libraries
            undefined_symbols.insert(symbol_name);
        }
    }

    // Write out the link graph
    if let Some(graph_path) = args.options.dump_link_graph.as_ref() {
        match std::fs::File::create(graph_path) {
            Ok(f) => {
                if let Err(e) = graph.write_dot_graph(BufWriter::new(f)) {
                    log::warn!("cannot not write link graph: {e}");
                }
            }
            Err(e) => {
                log::warn!("cannot not open {}: {e}", graph_path.display());
            }
        }
    }

    // Check errors
    if errored {
        std::process::exit(1);
    }

    let ignored_symbols =
        HashSet::from_iter(std::mem::take(&mut args.options.ignore_unresolved_symbol));

    // Finish building the link graph
    let finish_result = if args.options.warn_unresolved_symbols {
        graph.finish_unresolved(&ignored_symbols)
    } else {
        graph.finish(&ignored_symbols)
    };

    let mut graph = match finish_result {
        Ok(graph) => graph,
        Err(_) => {
            std::process::exit(1);
        }
    };

    // Run GC sections
    if args.options.gc_sections {
        graph.gc_sections(
            Some(&args.options.entry),
            args.options.require_defined.iter(),
        )?;

        if args.options.print_gc_sections {
            graph.print_discarded_sections();
        }
    }

    // Run merge bss
    if args.options.merge_bss {
        graph.merge_bss();
    }

    // Build the linked output from the graph
    let built = if args.options.merge_groups {
        graph.link_merge_groups()?
    } else {
        graph.link()?
    };

    std::fs::write(&args.options.output, built).context("cannot write output file")?;
    Ok(())
}

fn include_libenv_search_paths(args: &mut Cli) {
    if cfg!(windows)
        && let Some(libenv) = std::env::var_os("LIB")
    {
        for path in std::env::split_paths(&libenv) {
            args.options
                .library_path
                .push(path.normalize_lexically_cpp());
        }
    }
}

fn setup_global_logging(options: &CliOptions) {
    let mut max_level = log::Level::Info;
    if options.verbose >= 2 {
        max_level = log::Level::Trace;
    } else if options.verbose >= 1 {
        max_level = log::Level::Debug;
    }

    boflink_log::init_logger(CARGO_PKG_NAME, options.color_diagnostics, max_level)
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
            "# Copy the text below the dashed '---' line to a file named \"boflink.specs\" and run \"x86_64-w64-mingw32-gcc -specs=boflink.specs ...\"\n---"
        );
    }

    let current_exe = std::env::current_exe()
        .map(|exe| exe.into_os_string())
        .unwrap_or_else(|_| OsString::from(CARGO_PKG_NAME));

    println!(
        "*startfile:\n\
        \n\n\
        *endfile:\n\
        \n\n\
        *linker:\n\
        {current_exe}",
        current_exe = current_exe.display()
    );
}
