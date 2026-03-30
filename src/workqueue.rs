use crossbeam_channel::{Receiver, Sender};
use rayon::iter::{ParallelBridge, ParallelIterator};

/// Queue for spawning parallel tasks
pub struct ParallelWorkQueue<T> {
    sender: Sender<WorkTask<T>>,
    receiver: Receiver<WorkTask<T>>,
}

impl<T> ParallelWorkQueue<T> {
    /// Creates a new [`ParallelWorkQueue`] with no tasks
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the number of tasks in the queue
    pub fn len(&self) -> usize {
        self.receiver.len()
    }

    /// Returns `true` if the queue is empty
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Adds a task to the work queue
    pub fn push_back(&self, item: T) {
        let _ = self.sender.send(WorkTask {
            item,
            sender: self.sender.clone(),
        });
    }

    // TODO: Make invariant
    pub fn extender(&self, f: impl FnOnce(WorkExtender<T>)) {
        f(WorkExtender {
            sender: self.sender.clone(),
        })
    }

    /// Runs all of the queued tasks.
    ///
    /// Takes in a function `f` which gets invoked asynchronously passing the
    /// work queue items and a [`WorkExtender`] for adding more work to the
    /// queue dynamically.
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

/// Structure which allows adding work queue tasks during runtime
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
    /// Adds a task to the work queue this extender is from
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
