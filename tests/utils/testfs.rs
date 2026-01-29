use std::{
    io::Write,
    path::{Component, Path, PathBuf},
};

#[derive(Debug, Clone)]
pub struct TestFs {
    root: PathBuf,
}

#[allow(unused)]
impl TestFs {
    pub fn new(path: impl AsRef<Path>) -> std::io::Result<Self> {
        let mut root = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
            .join("boflink")
            .join("testout");
        root.push(normalize(path.as_ref()));
        std::fs::create_dir_all(&root)?;
        Ok(Self { root })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn create_dir(&self, path: impl AsRef<Path>) -> std::io::Result<()> {
        std::fs::create_dir(self.join_path(path))
    }

    pub fn create_file(&self, path: impl AsRef<Path>) -> std::io::Result<std::fs::File> {
        std::fs::File::create(self.join_path(path))
    }

    pub fn read(&self, path: impl AsRef<Path>) -> std::io::Result<Vec<u8>> {
        std::fs::read(self.join_path(path))
    }

    pub fn write(&self, path: impl AsRef<Path>, contents: impl AsRef<[u8]>) -> std::io::Result<()> {
        let mut f = self.create_file(path)?;
        f.write_all(contents.as_ref())?;
        Ok(())
    }

    pub fn join_path(&self, path: impl AsRef<Path>) -> PathBuf {
        self.root.join(normalize(path.as_ref()))
    }
}

fn normalize(path: impl AsRef<Path>) -> PathBuf {
    let mut normalized = PathBuf::new();

    for component in path.as_ref().components() {
        match component {
            Component::ParentDir => {
                if normalized.pop() {
                    panic!("path normalization traversed outside of root");
                }
            }
            Component::Normal(p) => {
                normalized.push(p);
            }
            _ => continue,
        }
    }

    normalized
}
