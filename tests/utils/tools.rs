#![allow(unused)]

use std::{
    ffi::{OsStr, OsString},
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use tempfile::{Builder, NamedTempFile, TempDir};

#[derive(Debug, Clone)]
pub struct Clang {
    exe: OsString,
    target: String,
    flags: Vec<OsString>,
    files: Vec<PathBuf>,
    stdin: String,
}

impl std::default::Default for Clang {
    fn default() -> Self {
        Self {
            exe: "clang".into(),
            #[cfg(windows)]
            target: "x86_64-pc-windows-msvc".into(),
            #[cfg(not(windows))]
            target: "x86_64-pc-windows-gnu".into(),
            files: Vec::new(),
            flags: Vec::new(),
            stdin: String::new(),
        }
    }
}

impl Clang {
    pub fn target(&mut self, target: &str) -> &mut Clang {
        self.target = target.to_string();
        self
    }

    pub fn file(&mut self, p: impl AsRef<Path>) -> &mut Clang {
        self.files.push(p.as_ref().to_owned());
        self
    }

    pub fn files<I: Iterator>(&mut self, p: I) -> &mut Clang
    where
        <I as Iterator>::Item: AsRef<Path>,
    {
        self.files.extend(p.map(|p| p.as_ref().to_owned()));
        self
    }

    pub fn flag(&mut self, flag: impl AsRef<OsStr>) -> &mut Clang {
        self.flags.push(flag.as_ref().to_owned());
        self
    }

    pub fn flags<I: Iterator>(&mut self, flags: I) -> &mut Clang
    where
        <I as Iterator>::Item: AsRef<OsStr>,
    {
        self.flags
            .extend(flags.map(|flag| flag.as_ref().to_owned()));
        self
    }

    pub fn compile_objs(&self) -> ToolOutput {
        let temp_dir = Builder::new()
            .prefix("boflink-out")
            .tempdir()
            .expect("failed creating temporary directory");

        let out_files = self
            .files
            .iter()
            .map(|file| {
                let filename = file
                    .file_name()
                    .unwrap_or_else(|| panic!("{} has no file name", file.display()));
                let mut outpath = temp_dir.as_ref().join(filename);
                outpath.set_extension("o");
                outpath
            })
            .collect::<Vec<_>>();

        for (out_path, src_path) in out_files.iter().zip(self.files.iter()) {
            let mut child = Command::new(&self.exe)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .stderr(Stdio::piped())
                .arg(format!("--target={}", self.target))
                .args(self.flags.iter())
                .arg("-c")
                .arg("-o")
                .arg(out_path)
                .arg(src_path)
                .spawn()
                .expect("failed running command");

            if !self.stdin.is_empty() {
                let pipe = child.stdin.as_mut().unwrap();
                pipe.write_all(self.stdin.as_bytes())
                    .expect("cannot write to stdin");
            }

            let output = child
                .wait_with_output()
                .expect("failed waiting for child process");

            if !output.status.success() {
                panic!("clang returned non-zero exit code");
            }
        }

        ToolOutput {
            dir: temp_dir,
            files: out_files,
        }
    }
}

#[derive(Debug)]
pub struct ToolOutput {
    dir: TempDir,
    files: Vec<PathBuf>,
}

impl ToolOutput {
    pub fn dir(&self) -> &Path {
        self.dir.as_ref()
    }

    pub fn paths(&self) -> &[PathBuf] {
        &self.files
    }
}

#[derive(Debug, Clone)]
pub struct Dlltool {
    exe: OsString,
    machine: String,
    dllname: String,
    deffile: PathBuf,
    flags: Vec<OsString>,
}

impl std::default::Default for Dlltool {
    fn default() -> Self {
        Self {
            exe: "llvm-dlltool".into(),
            machine: "i386:x86-64".into(),
            dllname: String::new(),
            deffile: PathBuf::new(),
            flags: Vec::new(),
        }
    }
}

impl Dlltool {
    pub fn machine(&mut self, machine: &str) -> &mut Dlltool {
        self.machine = machine.into();
        self
    }

    pub fn dllname(&mut self, dllname: &str) -> &mut Dlltool {
        self.dllname = dllname.into();
        self
    }

    pub fn def(&mut self, p: impl AsRef<Path>) -> &mut Dlltool {
        self.deffile = p.as_ref().to_owned();
        self
    }

    pub fn flag(&mut self, flag: impl AsRef<OsStr>) -> &mut Dlltool {
        self.flags.push(flag.as_ref().to_owned());
        self
    }

    pub fn flags<I: Iterator>(&mut self, flags: I) -> &mut Dlltool
    where
        <I as Iterator>::Item: AsRef<OsStr>,
    {
        self.flags
            .extend(flags.map(|flag| flag.as_ref().to_owned()));
        self
    }

    pub fn generate_importlib(&self) -> NamedTempFile {
        let outfile = NamedTempFile::with_suffix(".lib").expect("failed creating tempfile");

        let mut cmd = Command::new(&self.exe);
        cmd.args(["-m", &self.machine]);
        cmd.arg("-d");
        cmd.arg(&self.deffile);

        if !self.dllname.is_empty() {
            cmd.args(["-D", &self.dllname]);
        }

        cmd.arg("-l");
        cmd.arg(outfile.path());

        if !self.flags.is_empty() {
            cmd.args(&self.flags);
        }

        let res = cmd.status().expect("failed running command");
        if !res.success() {
            panic!("llvm-dlltool returned non-zero exit code");
        }

        outfile
    }
}

pub fn clang() -> Clang {
    Default::default()
}

pub fn asm1(src: impl AsRef<str>) -> ToolOutput {
    let mut srcfile = NamedTempFile::with_suffix(".S").expect("failed creating source tempfile");
    srcfile
        .write_all(src.as_ref().as_bytes())
        .expect("failed writing source contents");

    clang().file(&srcfile).compile_objs()
}

pub fn asm<I: Iterator>(srcs: I) -> ToolOutput
where
    <I as Iterator>::Item: AsRef<str>,
{
    let srcdir = Builder::new()
        .prefix("boflink-src")
        .tempdir()
        .expect("failed creating temporary directory");

    let mut c = clang();
    for (i, src) in srcs.enumerate() {
        let filename = format!("file{i}.S");
        let srcpath = srcdir.path().join(filename);
        std::fs::write(&srcpath, src.as_ref().as_bytes()).expect("failed writing source file");
        c.file(srcpath);
    }

    c.compile_objs()
}

pub fn dlltool(def: impl AsRef<str>) -> NamedTempFile {
    let mut srcfile = NamedTempFile::with_suffix(".def").expect("failed creating def tempfile");
    srcfile
        .write_all(def.as_ref().as_bytes())
        .expect("failed writing def file contents");

    Dlltool::default().def(&srcfile).generate_importlib()
}
