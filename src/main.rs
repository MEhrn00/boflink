use std::{
    collections::HashSet,
    ffi::OsString,
    io::{BufWriter, IsTerminal},
    path::{Path, PathBuf},
    process::ExitCode,
};

use anyhow::{Context, Result, anyhow, bail};
use boflink_stdext::{path::PathExt, time::DurationExt};
use bstr::ByteSlice;
use bumpalo::Bump;
use log::{error, info, warn};
use object::{Object, ObjectSymbol, coff::CoffFile};
use typed_arena::Arena;

use crate::{
    archive::{LinkArchive, LinkArchiveMemberVariant},
    bofapi::ApiSymbols,
    cli::{CARGO_PKG_NAME, Cli, CliOptions, InputArg, InputArgVariant},
    directives::{LinkerDirective, parse_linker_directives},
    graph::LinkGraph,
    linker::{CoffPath, LinkContext, LinkerTargetArch, check_errored},
};

mod archive;
mod bofapi;
mod cli;
mod coff;
mod directives;
mod graph;
mod linker;

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
        info!("{}", args.render_version());
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

    let print_timing = args.options.print_timing;
    let link_result = run_linker(args);

    let elapsed = std::time::Instant::now() - it;
    if print_timing {
        info!("link time: {}", elapsed.display());
    }

    link_result
}

/// Runs the linker with the command line arguments
fn run_linker(mut cli: Cli) -> anyhow::Result<()> {
    let input_args = std::mem::take(&mut cli.inputs);

    let bump = Bump::new();
    let inputs_arena = Arena::with_capacity(input_args.len());
    let mut ctx = LinkContext::new(&bump, &inputs_arena, cli.options);
    include_libenv_search_paths(&mut ctx);

    // Process the input files
    for input_arg in input_args {
        if let Err(e) = read_input_arg(&mut ctx, input_arg) {
            error!(logger: ctx.logger(), "{e:#}");
        }
    }

    // Ensure that the entrypoint is extracted from any archives
    ensure_entrypoint(&mut ctx);

    // Check for errors reading inputs
    check_errored(&mut ctx);
    if ctx.input_coffs.is_empty() {
        bail!("no input files");
    }

    // Get target architecture for the linker
    let target_arch = identify_target_architecture(&ctx)
        .context("cannot detect target architecture from input files")?;

    // Read symbols from custom API or use the built-in Beacon API symbols
    read_api_symbols(&mut ctx, target_arch)?;

    // Build the graph
    let graph_arena = ctx.spec_graph.alloc_arena();
    let mut graph = ctx.spec_graph.alloc_graph(&graph_arena, target_arch);

    // Add COFFs to the link graph
    add_coff_inputs(&mut ctx, &mut graph);

    // Resolve symbols
    resolve_symbols(&mut ctx, &mut graph);

    // Dump the current state of the link graph
    dump_link_graph(&ctx, &graph);

    // Check for errors
    check_errored(&mut ctx);

    // Finish building the link graph
    let ignored_symbols =
        HashSet::from_iter(std::mem::take(&mut ctx.options.ignore_unresolved_symbol));

    let finish_result = if ctx.options.warn_unresolved_symbols {
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
    if ctx.options.gc_sections {
        graph.gc_sections(Some(&ctx.options.entry), ctx.options.require_defined.iter())?;

        if ctx.options.print_gc_sections {
            graph.print_discarded_sections();
        }
    }

    // Run merge bss
    if ctx.options.merge_bss {
        graph.merge_bss();
    }

    // Build the linked output from the graph
    let built = if ctx.options.merge_groups {
        graph.link_merge_groups()?
    } else {
        graph.link()?
    };

    std::fs::write(&ctx.options.output, built).context("cannot write output file")?;
    Ok(())
}

fn include_libenv_search_paths(args: &mut LinkContext) {
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

fn read_input_arg<'a>(ctx: &mut LinkContext<'a>, input_arg: InputArg) -> anyhow::Result<()> {
    match input_arg.variant {
        InputArgVariant::File(file_path) => {
            let buffer = std::fs::read(&file_path)
                .with_context(|| format!("cannot open {}", file_path.display()))?;
            let (file_path, buffer) = ctx.inputs_arena.alloc((file_path, buffer));

            if object_is_archive(buffer.as_slice()) {
                let archive = LinkArchive::parse(buffer.as_slice())
                    .with_context(|| format!("cannot parse {}", file_path.display()))?;

                if input_arg.context.in_whole_archive {
                    read_archive_members(ctx, file_path.as_path(), archive)
                        .with_context(|| format!("{}", file_path.display()))?;
                } else if !ctx.lazy_archives.contains_key(file_path.as_path()) {
                    ctx.lazy_archives.insert(file_path.as_path(), archive);
                }
            } else {
                let coff: CoffFile = CoffFile::parse(buffer.as_slice())
                    .with_context(|| format!("cannot parse {}", file_path.display()))?;

                if let indexmap::map::Entry::Vacant(coff_entry) = ctx.input_coffs.entry(CoffPath {
                    file_path: file_path.as_path(),
                    member_path: None,
                }) {
                    ctx.spec_graph.add_coff(&coff);
                    coff_entry.insert(coff);
                }
            }
        }
        InputArgVariant::Library(library_name) => {
            let library_name = library_name.to_string_lossy().to_string();
            if !ctx.opened_library_names.contains(&library_name) {
                let (library_path, library_buffer) =
                    find_library(&ctx.options.library_path, &library_name)
                        .with_context(|| format!("unable to find library -l{library_name}"))?;

                ctx.opened_library_names.insert(library_name);

                if input_arg.context.in_whole_archive {
                    let (library_path, library_buffer) =
                        ctx.inputs_arena.alloc((library_path, library_buffer));
                    let archive = LinkArchive::parse(library_buffer.as_slice())
                        .with_context(|| format!("cannot parse {}", library_path.display()))?;

                    read_archive_members(ctx, library_path.as_path(), archive)
                        .with_context(|| format!("{}", library_path.display()))?;
                } else if !ctx.lazy_archives.contains_key(library_path.as_path()) {
                    let (library_path, library_buffer) =
                        ctx.inputs_arena.alloc((library_path, library_buffer));
                    let archive = LinkArchive::parse(library_buffer.as_slice())
                        .with_context(|| format!("cannot parse {}", library_path.display()))?;

                    ctx.lazy_archives.insert(library_path.as_path(), archive);
                }
            }
        }
    }

    Ok(())
}

fn read_archive_members<'a>(
    ctx: &mut LinkContext<'a>,
    path: &'a Path,
    archive: LinkArchive<'a>,
) -> anyhow::Result<()> {
    for member in archive.coff_members() {
        let (member_path, coff) = member?;

        if let indexmap::map::Entry::Vacant(coff_entry) = ctx.input_coffs.entry(CoffPath {
            file_path: path,
            member_path: Some(member_path),
        }) {
            ctx.spec_graph.add_coff(&coff);
            coff_entry.insert(coff);
        }
    }

    Ok(())
}

fn object_is_archive(buffer: &[u8]) -> bool {
    buffer
        .get(..object::archive::MAGIC.len())
        .is_some_and(|magic| magic == object::archive::MAGIC)
}

fn ensure_entrypoint<'a>(ctx: &mut LinkContext<'a>) {
    let entry_symbol = ctx.options.entry.as_str();
    for coff in ctx.input_coffs.values() {
        for symbol in coff.symbols() {
            if symbol.is_global()
                && symbol.is_definition()
                && symbol.name().is_ok_and(|name| name == entry_symbol)
            {
                return;
            }
        }
    }

    for (archive_path, archive) in &ctx.lazy_archives {
        for symbol in archive.symbols() {
            let Ok(symbol) = symbol else {
                return;
            };
            if symbol.name() != entry_symbol {
                continue;
            }

            let Ok((member_path, LinkArchiveMemberVariant::Coff(coff_member))) = symbol.extract()
            else {
                return;
            };
            ctx.input_coffs.insert(
                CoffPath {
                    file_path: archive_path,
                    member_path: Some(member_path),
                },
                coff_member,
            );
            return;
        }
    }
}

fn find_library(search_paths: &[PathBuf], name: &str) -> Option<(PathBuf, Vec<u8>)> {
    let try_open_path = |path: &Path| -> Option<Vec<u8>> {
        std::fs::read(path)
            .inspect_err(|e| log::debug!("attempt to open {} failed: {e}", path.display()))
            .ok()
    };

    if let Some(filename) = name.strip_prefix(':') {
        search_paths.iter().find_map(|search_path| {
            let full_path = search_path.join(filename);
            try_open_path(&full_path).map(|buffer| (full_path, buffer))
        })
    } else {
        let patterns = [
            ("lib", name, ".dll.a"),
            ("", name, ".dll.a"),
            ("lib", name, ".a"),
            ("", name, ".lib"),
            ("lib", name, ".lib"),
            ("", name, ".a"),
        ];

        search_paths.iter().find_map(|search_path| {
            patterns.into_iter().find_map(|(prefix, name, ext)| {
                let filename = format!("{prefix}{name}{ext}");
                let full_path = search_path.join(filename);
                try_open_path(&full_path).map(|buffer| (full_path, buffer))
            })
        })
    }
}

fn identify_target_architecture(ctx: &LinkContext) -> Option<LinkerTargetArch> {
    if let Some(machine) = ctx.options.machine {
        return Some(machine.into());
    }
    for coff in ctx.input_coffs.values() {
        if let Ok(arch) = LinkerTargetArch::try_from(coff.architecture()) {
            return Some(arch);
        }
    }
    None
}

fn read_api_symbols<'a>(
    ctx: &mut LinkContext<'a>,
    target_arch: LinkerTargetArch,
) -> anyhow::Result<()> {
    ctx.api_symbols = if let Some(custom_api) = open_custom_api(ctx) {
        let (api_path, api_buffer) = ctx.inputs_arena.alloc(custom_api?);
        let api_archive = LinkArchive::parse(api_buffer.as_slice())
            .with_context(|| format!("cannot parse {}", api_path.display()))?;
        ApiSymbols::new(api_path.as_path(), api_archive)
            .with_context(|| format!("{}", api_path.display()))?
    } else {
        ApiSymbols::beacon(ctx.bump, target_arch)
    };
    Ok(())
}

fn open_custom_api<'a>(ctx: &mut LinkContext<'a>) -> Option<anyhow::Result<(PathBuf, Vec<u8>)>> {
    ctx.options.custom_api.as_ref().map(|custom_api| {
        std::fs::read(custom_api)
            .map(|buffer| (Path::new(custom_api).normalize_lexically_cpp(), buffer))
            .or_else(|e| {
                if e.kind() == std::io::ErrorKind::NotFound {
                    let custom_api = custom_api.to_string_lossy();
                    let found = find_library(&ctx.options.library_path, custom_api.as_ref())
                        .with_context(|| {
                            format!("unable to find --custom-api: {}", custom_api.as_ref())
                        })?;
                    ctx.opened_library_names.insert(custom_api.to_string());
                    return Ok(found);
                }
                Err(anyhow!("cannot open {}: {e}", custom_api.display()))
            })
    })
}

fn add_coff_inputs<'a>(ctx: &mut LinkContext<'a>, graph: &mut LinkGraph<'a, 'a>) {
    let coffs = std::mem::take(&mut ctx.input_coffs);
    for (path, coff) in coffs {
        if let Err(e) = add_coff_file(ctx, graph, path, coff) {
            error!(logger: ctx.logger(), "{e:#}");
        }
    }
}

fn add_coff_file<'a>(
    ctx: &mut LinkContext<'a>,
    graph: &mut LinkGraph<'a, 'a>,
    path: CoffPath<'a>,
    coff: CoffFile<'a>,
) -> anyhow::Result<()> {
    let drecvtes = parse_linker_directives(ctx.bump, &coff)
        .with_context(|| format!("cannot parse {}", path))?;
    for directive in drecvtes {
        let LinkerDirective::Defaultlib(defaultlib) = directive else {
            continue;
        };
        let defaultlib = defaultlib.to_str_lossy();
        if ctx.opened_library_names.contains(defaultlib.as_ref()) {
            continue;
        }
        let (library_path, buffer) = find_library(&ctx.options.library_path, &defaultlib)
            .with_context(|| format!("{path}: unable to find library {defaultlib}"))?;
        ctx.opened_library_names.insert(defaultlib.to_string());
        if ctx.lazy_archives.contains_key(library_path.as_path()) {
            continue;
        }
        let (library_path, buffer) = ctx.inputs_arena.alloc((library_path, buffer));
        let archive = LinkArchive::parse(buffer.as_slice())
            .with_context(|| format!("{path}: cannot parse {}", library_path.display()))?;
        ctx.lazy_archives.insert(library_path.as_path(), archive);
    }

    graph.add_coff(path.file_path, path.member_path, &coff)
}

fn resolve_symbols<'a>(ctx: &mut LinkContext<'a>, graph: &mut LinkGraph<'a, 'a>) {
    loop {
        let resolvable_symbols = graph
            .archive_resolvable_externals()
            .filter(|symbol| !ctx.unresolved_symbols.contains(symbol))
            .collect::<Vec<_>>();

        // No resolvable symbols are left
        if resolvable_symbols.is_empty() {
            break;
        }

        for symbol_name in resolvable_symbols {
            match resolve_symbol(ctx, graph, symbol_name) {
                Ok(false) => {
                    ctx.unresolved_symbols.insert(symbol_name);
                }
                Err(e) => {
                    error!(logger: ctx.logger(), "{e:#}");
                }
                _ => (),
            }
        }
    }

    dump_link_graph(ctx, graph);
}

fn resolve_symbol<'a>(
    ctx: &mut LinkContext<'a>,
    graph: &mut LinkGraph<'a, 'a>,
    symbol_name: &'a str,
) -> anyhow::Result<bool> {
    if let Some(api_import) = ctx.api_symbols.get(symbol_name) {
        graph
            .add_api_import(symbol_name, api_import)
            .with_context(|| format!("{}", ctx.api_symbols.archive_path().display()))?;
        return Ok(true);
    }

    for i in 0..ctx.lazy_archives.len() {
        match resolve_symbol_from(ctx, graph, symbol_name, i) {
            Ok(true) => return Ok(true),
            Err(e) => {
                error!(logger: ctx.logger(), "{e:#}");
            }
            _ => (),
        };
    }

    Ok(false)
}

fn resolve_symbol_from<'a>(
    ctx: &mut LinkContext<'a>,
    graph: &mut LinkGraph<'a, 'a>,
    symbol_name: &'a str,
    archive_index: usize,
) -> anyhow::Result<bool> {
    let (library_path, library) = ctx.lazy_archives.get_index(archive_index).unwrap();
    let Some((member_path, member)) = library.extract_symbol(symbol_name)? else {
        return Ok(false);
    };

    match member {
        LinkArchiveMemberVariant::Coff(coff) => {
            add_coff_file(
                ctx,
                graph,
                CoffPath {
                    file_path: library_path,
                    member_path: Some(member_path),
                },
                coff,
            )?;
        }
        LinkArchiveMemberVariant::Import(import_file) => {
            graph.add_library_import(symbol_name, &import_file)?;
        }
    }

    Ok(true)
}

fn dump_link_graph(ctx: &LinkContext, graph: &LinkGraph) {
    let Some(path) = ctx.options.dump_link_graph.as_ref() else {
        return;
    };
    match std::fs::File::create(path) {
        Ok(f) => {
            if let Err(e) = graph.write_dot_graph(BufWriter::new(f)) {
                warn!("cannot write link graph: {e}");
            }
        }
        Err(e) => {
            warn!("cannot open {}: {e}", path.display());
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
