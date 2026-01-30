use std::time::Duration;

#[derive(Debug, Clone)]
pub struct DurationFormatter<'a>(&'a Duration);

impl std::fmt::Display for DurationFormatter<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.0 >= &Duration::from_secs(1) {
            write!(f, "{:.3}s", self.0.as_secs_f64())
        } else if self.0 >= &Duration::from_millis(1) {
            write!(f, "{:.3}ms", self.0.as_micros() as f64 / 1000f64)
        } else if self.0 >= &Duration::from_micros(1) {
            write!(f, "{:.3}us", self.0.as_nanos() as f64 / 1000f64)
        } else {
            write!(f, "{}ns", self.0.as_nanos())
        }
    }
}

impl<'a> DurationFormatter<'a> {
    pub fn new(d: &'a std::time::Duration) -> Self {
        Self(d)
    }
}
