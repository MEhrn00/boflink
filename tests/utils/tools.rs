use std::{
    ffi::{OsStr, OsString},
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use crate::utils::testfs::TestFs;

#[derive(Debug, Clone)]
pub struct Clang {
    exe: OsString,
    target: String,
    flags: Vec<OsString>,
    files: Vec<PathBuf>,
    stdin: String,
    out_dir: PathBuf,
}

impl std::default::Default for Clang {
    fn default() -> Self {
        Self {
            exe: option_env!("BOFLINK_TEST_CLANG").unwrap_or("clang").into(),
            #[cfg(windows)]
            target: "x86_64-pc-windows-msvc".into(),
            #[cfg(not(windows))]
            target: "x86_64-pc-windows-gnu".into(),
            files: Vec::new(),
            flags: Vec::new(),
            stdin: String::new(),
            out_dir: PathBuf::new(),
        }
    }
}

#[allow(unused)]
impl Clang {
    pub fn target(&mut self, target: &str) -> &mut Clang {
        self.target = target.to_string();
        self
    }

    pub fn out_dir(&mut self, path: impl AsRef<Path>) -> &mut Clang {
        self.out_dir = path.as_ref().to_owned();
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

    pub fn compile_objs(&self) -> Vec<PathBuf> {
        let mut out_paths = Vec::with_capacity(self.files.len());
        for src_path in self.files.iter() {
            let mut out_path = PathBuf::new();
            if !self.out_dir.as_os_str().is_empty() {
                out_path.push(&self.out_dir);
                let filename = src_path.file_name().unwrap_or_else(|| {
                    panic!("{} has not file name component", src_path.display())
                });
                out_path.push(filename);
                out_path.set_extension("o");
            } else {
                out_path.push(src_path);
                out_path.set_extension("o");
            }

            let mut child = Command::new(&self.exe)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .stderr(Stdio::piped())
                .arg(format!("--target={}", self.target))
                .args(self.flags.iter())
                .arg("-c")
                .arg("-o")
                .arg(&out_path)
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
                let stdout = output.stdout;
                let stderr = output.stderr;
                panic!(
                    "clang returned non-zero exit code\nSTDOUT:\n{}\nSTDERR:\n{}\n",
                    String::from_utf8_lossy(&stdout),
                    String::from_utf8_lossy(&stderr)
                );
            }

            out_paths.push(out_path);
        }

        out_paths
    }
}

#[derive(Debug, Clone)]
pub struct Dlltool {
    exe: OsString,
    machine: String,
    dllname: String,
    deffile: PathBuf,
    libpath: PathBuf,
    flags: Vec<OsString>,
}

impl std::default::Default for Dlltool {
    fn default() -> Self {
        Self {
            exe: option_env!("BOFLINK_TEST_DLLTOOL")
                .unwrap_or("llvm-dlltool")
                .into(),
            machine: "i386:x86-64".into(),
            dllname: String::new(),
            deffile: PathBuf::new(),
            libpath: PathBuf::new(),
            flags: Vec::new(),
        }
    }
}

#[allow(unused)]
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

    pub fn lib(&mut self, p: impl AsRef<Path>) -> &mut Dlltool {
        self.libpath = p.as_ref().to_owned();
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

    pub fn generate_importlib(&self) -> PathBuf {
        let mut cmd = Command::new(&self.exe);
        cmd.args(["-m", &self.machine]);
        cmd.arg("-d");
        cmd.arg(&self.deffile);

        if !self.dllname.is_empty() {
            cmd.args(["-D", &self.dllname]);
        }

        cmd.arg("-l");

        let mut outpath = PathBuf::new();
        if !self.libpath.as_os_str().is_empty() {
            outpath = self.libpath.clone();
        } else {
            outpath = self.deffile.clone();
            outpath.set_extension("lib");
        }
        cmd.arg(&outpath);

        if !self.flags.is_empty() {
            cmd.args(&self.flags);
        }

        let res = cmd.status().expect("failed running command");
        if !res.success() {
            panic!("llvm-dlltool returned non-zero exit code");
        }

        outpath
    }
}

pub fn asm<N: AsRef<str>, C: AsRef<str>>(fs: &TestFs) -> impl FnMut(N, C) -> PathBuf {
    move |name, content| {
        let mut path = PathBuf::from(name.as_ref());
        path.set_extension("S");
        fs.write(&path, content.as_ref().as_bytes())
            .expect("failed writing source file");
        Clang::default()
            .file(fs.join_path(path))
            .compile_objs()
            .into_iter()
            .next()
            .unwrap()
    }
}

pub fn dlltool<N: AsRef<str>, C: AsRef<str>>(fs: &TestFs) -> impl FnMut(N, C) -> PathBuf {
    move |name, content| {
        let mut path = PathBuf::from(name.as_ref());
        path.set_extension("def");
        fs.write(&path, content.as_ref().as_bytes())
            .expect("failed writing def file");
        Dlltool::default()
            .def(fs.join_path(path))
            .generate_importlib()
    }
}
