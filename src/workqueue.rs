use crossbeam_channel::{Receiver, Sender};
use rayon::iter::{ParallelBridge, ParallelIterator};

pub struct ParallelWorkQueue<T> {
    sender: Sender<WorkTask<T>>,
    receiver: Receiver<WorkTask<T>>,
}

impl<T> ParallelWorkQueue<T> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.receiver.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn push_back(&self, item: T) {
        let _ = self.sender.send(WorkTask {
            item,
            sender: self.sender.clone(),
        });
    }

    pub fn extender(&self, f: impl FnOnce(WorkExtender<T>)) {
        f(WorkExtender {
            sender: self.sender.clone(),
        })
    }

    pub fn run<F>(self, f: F)
    where
        T: Send + Sync,
        F: Fn(WorkExtender<T>, T) + Send + Sync,
    {
        drop(self.sender);
        self.receiver.into_iter().par_bridge().for_each(|task| {
            let extender = WorkExtender {
                sender: task.sender,
            };
            f(extender, task.item);
        });
    }
}

impl<T> std::default::Default for ParallelWorkQueue<T> {
    fn default() -> Self {
        let (sender, receiver) = crossbeam_channel::unbounded();
        Self { sender, receiver }
    }
}

pub struct WorkExtender<T> {
    sender: Sender<WorkTask<T>>,
}

impl<T> Clone for WorkExtender<T> {
    fn clone(&self) -> Self {
        Self {
            sender: self.sender.clone(),
        }
    }
}

impl<T> WorkExtender<T>
where
    T: Send + Sync,
{
    pub fn add(&self, item: T) {
        let _ = self.sender.send(WorkTask {
            item,
            sender: self.sender.clone(),
        });
    }
}

struct WorkTask<T> {
    item: T,
    sender: Sender<WorkTask<T>>,
}
