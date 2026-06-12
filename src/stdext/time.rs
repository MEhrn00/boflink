use std::time::Duration;

/// Extension trait for [`std::time::Duration`].
pub trait DurationExt {
    fn display(&self) -> DurationDisplay<'_>;
}

impl DurationExt for std::time::Duration {
    fn display(&self) -> DurationDisplay<'_> {
        DurationDisplay { inner: self }
    }
}

/// [`std::fmt::Display`] implementation for a [`std::time::Duration`].
///
/// This will automatically compute significance level such that the time is
/// less than 1000th of a unit and will display the unit suffix.
///
/// The time is internally converted to a `f64` and allows specifying precision
/// in the format specifier.
#[derive(Debug)]
pub struct DurationDisplay<'a> {
    inner: &'a Duration,
}

impl std::fmt::Display for DurationDisplay<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.inner < &Duration::from_nanos(1_000) {
            write!(f, "{}ns", self.inner.as_nanos())?;
            return Ok(());
        }

        let (convert, suffix) = if self.inner < &Duration::from_micros(1_000) {
            (Duration::from_micros(1), "µs")
        } else if self.inner < &Duration::from_millis(1_000) {
            (Duration::from_millis(1), "ms")
        } else {
            (Duration::from_secs(1), "s")
        };

        if let Some(precision) = f.precision() {
            write!(
                f,
                "{:.*}{suffix}",
                precision,
                self.inner.div_duration_f64(convert)
            )
        } else {
            write!(f, "{}{suffix}", self.inner.div_duration_f64(convert))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::DurationExt;

    #[test]
    fn duration_formatting() {
        let tests = [
            (Duration::from_secs(1), None, "1s"),
            (Duration::from_secs(1), Some(3), "1.000s"),
            (Duration::from_nanos_u128(100), None, "100ns"),
            (Duration::from_millis(100), Some(2), "100.00ms"),
            (Duration::new(1, 1_000_000), None, "1.001s"),
        ];

        for (duration, precision, expected) in tests {
            let formatted = if let Some(precision) = precision {
                format!("{:.precision$}", duration.display())
            } else {
                format!("{}", duration.display())
            };
            assert_eq!(
                formatted, expected,
                "duration = {duration:?}, precision = {precision:?}"
            );
        }
    }
}
