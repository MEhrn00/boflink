#[cfg(feature = "parking_lot")]
use parking_lot_mutex as inner;

#[cfg(not(feature = "parking_lot"))]
use std_mutex as inner;

#[repr(transparent)]
pub struct Mutex<T: ?Sized>(inner::Mutex<T>);

impl<T> Mutex<T> {
    pub const fn new(val: T) -> Mutex<T> {
        Self(inner::Mutex::new(val))
    }
}

impl<T: ?Sized> Mutex<T> {
    pub fn lock(&self) -> MutexGuard<'_, T> {
        self.0.lock()
    }
}

impl<T: std::fmt::Debug + ?Sized> std::fmt::Debug for Mutex<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(&self.0, f)
    }
}

impl<T: std::default::Default> std::default::Default for Mutex<T> {
    fn default() -> Self {
        Self(Default::default())
    }
}

pub type MutexGuard<'a, T> = inner::MutexGuard<'a, T>;

#[cfg(feature = "parking_lot")]
mod parking_lot_mutex {
    pub type Mutex<T> = parking_lot::Mutex<T>;
    pub type MutexGuard<'a, T> = parking_lot::MutexGuard<'a, T>;
}

#[cfg(not(feature = "parking_lot"))]
mod std_mutex {
    #[derive(Default, Debug)]
    #[repr(transparent)]
    pub struct Mutex<T: ?Sized>(std::sync::Mutex<T>);

    impl<T> Mutex<T> {
        pub const fn new(val: T) -> Self {
            Self(std::sync::Mutex::new(val))
        }
    }

    impl<T: ?Sized> Mutex<T> {
        pub fn lock(&self) -> MutexGuard<'_, T> {
            self.0.lock().unwrap()
        }
    }

    pub type MutexGuard<'a, T> = std::sync::MutexGuard<'a, T>;
}
