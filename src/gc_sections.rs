use crate::{context::LinkContext, linker::Linker, timing::ScopedTimer};

impl<'a> Linker<'a> {
    pub fn do_gc(&mut self, ctx: &LinkContext<'a>) {
        let _timer = ScopedTimer::msg("--gc-sections");
    }
}
