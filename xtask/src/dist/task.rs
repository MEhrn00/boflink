use std::{
    collections::VecDeque,
    error::Error,
    io::{BufWriter, Cursor, Read, Write},
    path::PathBuf,
    sync::Mutex,
    time::UNIX_EPOCH,
};

use chrono::Utc;
use flate2::{Compression, write::GzEncoder};
use sha2::Digest;
use tar::Header;
use zip::{ZipWriter, write::SimpleFileOptions};

use crate::utils;

use super::sha256::Sha256Writer;

const INSTALL_SCRIPT: &str = r#"#!/bin/sh
PREFIX="${PREFIX:-$HOME/.local}"

/usr/bin/install -v -m 755 boflink $PREFIX/bin/boflink
/usr/bin/ln -vsf -T boflink $PREFIX/bin/ld.boflink
"#;

pub fn dist() -> Result<(), Box<dyn Error>> {
    if !std::env::args_os().skip(2).any(|arg| arg == "--skip-tests") {
        let _ = utils::shell::run_cargo(["test"]);
    }

    let mut build_targets = Vec::new();
    let mut target_flag_found = false;
    for arg in std::env::args().skip(2) {
        if let Some(target) = arg.strip_prefix("--target=") {
            build_targets.extend(target.split(',').map(String::from));
        } else if arg == "-t" || arg == "--target" {
            target_flag_found = true;
        } else if target_flag_found {
            target_flag_found = false;
            build_targets.extend(arg.split(',').map(String::from));
        }
    }

    if build_targets.is_empty() {
        build_targets.push(utils::env::rustc_host()?);
    }

    build_targets.sort();
    build_targets.dedup();

    let version = utils::metadata::package_version("boflink")?;
    let workspaceroot = PathBuf::from(utils::metadata::workspace_root()?);
    let targetdir = PathBuf::from(utils::metadata::target_directory()?);
    let distdir = targetdir.join("dist");
    std::fs::create_dir_all(&distdir)?;

    utils::shell::run_cargo(
        ["build", "--release"].into_iter().chain(
            build_targets
                .iter()
                .flat_map(|target| ["--target", target.as_str()]),
        ),
    )?;

    let thread_count = std::thread::available_parallelism()
        .map(|v| v.get())
        .unwrap_or(1)
        .min(build_targets.len());

    let tasks = Mutex::new(VecDeque::from_iter(build_targets));

    std::thread::scope(|scope| -> Result<(), std::io::Error> {
        let mut thrds = VecDeque::with_capacity(thread_count);

        for _ in 0..thread_count {
            thrds.push_back(scope.spawn(|| -> Result<(), std::io::Error> {
                while let Some(target) = tasks.lock().unwrap().pop_front() {
                    let builddir = targetdir.join(&target).join("release");

                    let windows_build = target.contains("windows");
                    let linux_build = target.contains("linux");

                    let binext = windows_build.then_some("exe");
                    let distext = if windows_build { "zip" } else { "tar.gz" };

                    let distname = format!("boflink-v{version}-{target}");
                    let distfilename = PathBuf::from(format!("{distname}.{distext}"));
                    let distsumfilename = PathBuf::from(format!("{distname}.{distext}.sha256"));
                    let distname = PathBuf::from(distname);

                    if linux_build {
                        let mut tarbuilder = tar::Builder::new(GzEncoder::new(
                            Sha256Writer::new(BufWriter::new(std::fs::File::create(
                                distdir.join(&distfilename),
                            )?)),
                            Compression::default(),
                        ));

                        tarbuilder.append_path_with_name(
                            builddir
                                .join("boflink")
                                .with_extension(binext.unwrap_or_default()),
                            distname
                                .join("boflink")
                                .with_extension(binext.unwrap_or_default()),
                        )?;

                        tarbuilder.append_path_with_name(
                            workspaceroot.join("LICENSE"),
                            distname.join("LICENSE"),
                        )?;

                        let mut header = Header::new_gnu();
                        header.set_size(INSTALL_SCRIPT.len() as u64);
                        header.set_mode(0o755);
                        header.set_mtime(
                            std::time::SystemTime::now()
                                .duration_since(UNIX_EPOCH)
                                .unwrap()
                                .as_secs(),
                        );
                        tarbuilder.append_data(
                            &mut header,
                            distname.join("install"),
                            INSTALL_SCRIPT.as_bytes(),
                        )?;

                        let sha256sum = tarbuilder.into_inner()?.finish()?.finalize();
                        std::fs::write(
                            distdir.join(&distsumfilename),
                            format!("{}  {}\n", hex::encode(sha256sum), distfilename.display()),
                        )?;
                    } else if windows_build {
                        let mut zipbuilder = ZipWriter::new(Cursor::new(Vec::new()));

                        let filepath = builddir
                            .join("boflink")
                            .with_extension(binext.unwrap_or_default());

                        let mut file = std::fs::File::open(&filepath)?;

                        let modified =
                            chrono::DateTime::<Utc>::from(file.metadata()?.modified()?).naive_utc();

                        zipbuilder.start_file_from_path(
                            distname
                                .join("boflink")
                                .with_extension(binext.unwrap_or_default()),
                            SimpleFileOptions::default()
                                .unix_permissions(0o755)
                                .last_modified_time(
                                    zip::DateTime::try_from(modified)
                                        .map_err(std::io::Error::other)?,
                                ),
                        )?;

                        let mut buffer = Vec::new();
                        file.read_to_end(&mut buffer)?;

                        zipbuilder.write_all(buffer.as_slice())?;

                        buffer.clear();

                        let filepath = workspaceroot.join("LICENSE");
                        let mut file = std::fs::File::open(&filepath)?;

                        let modified =
                            chrono::DateTime::<Utc>::from(file.metadata()?.modified()?).naive_utc();

                        zipbuilder.start_file_from_path(
                            distname.join("LICENSE"),
                            SimpleFileOptions::default()
                                .unix_permissions(0o644)
                                .last_modified_time(
                                    zip::DateTime::try_from(modified)
                                        .map_err(std::io::Error::other)?,
                                ),
                        )?;

                        file.read_to_end(&mut buffer)?;
                        zipbuilder.write_all(buffer.as_slice())?;

                        buffer.clear();

                        let result = zipbuilder.finish()?.into_inner();
                        let sha256sum: [u8; 32] = sha2::Sha256::digest(result.as_slice()).into();

                        std::fs::write(distdir.join(&distfilename), result.as_slice())?;

                        std::fs::write(
                            distdir.join(&distsumfilename),
                            format!(
                                "SHA256 hash of .\\{}:\n{}\nCertUtil: -hashfile command completed successfully.\n",
                                distfilename.display(),
                                hex::encode(sha256sum)
                            ),
                        )?;
                    }
                }

                Ok(())
            }));
        }

        while let Some(thr) = thrds.pop_front() {
            thr.join().unwrap()?;
        }

        Ok(())
    })?;

    Ok(())
}
