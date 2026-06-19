use anyhow::Context;
use bstr::{BStr, ByteSlice};
use bumpalo::Bump;
use object::{Object, ObjectSection, coff::CoffFile, pe::IMAGE_SCN_LNK_INFO};

#[derive(Debug, PartialEq, Eq, Hash)]
pub enum LinkerDirective<'a> {
    Defaultlib(&'a BStr),
    Other(&'a BStr),
}

#[derive(Debug, PartialEq, Eq, Hash)]
enum WinsplitState {
    Init,
    InQuote,
    NoQuote,
}

fn split_once_exclusive<T, F: FnMut(&T) -> bool>(slce: &[T], pred: F) -> Option<(&[T], &[T])> {
    let index = slce.iter().position(pred)?;
    Some((&slce[..index], &slce[index..]))
}

fn is_whitespace_or_null(b: u8) -> bool {
    b.is_ascii_whitespace() || b == 0
}

fn is_special(b: u8) -> bool {
    is_whitespace_or_null(b) || b == b'\\' || b == b'"'
}

fn trim_ascii_space_or_null(data: &[u8]) -> &[u8] {
    data.trim_start_with(|c| c == ' ' || c == '\0')
}

fn parse_backslash<'a>(data: &'a [u8], arg: &mut Vec<u8>) -> &'a [u8] {
    let mut remaining = data;
    remaining = remaining.trim_start_with(|c| c == '\\');
    let count = data.len() - remaining.len();
    if remaining.first() == Some(&b'"') {
        arg.extend(std::iter::repeat_n(b'\\', count / 2));
        if !count.is_multiple_of(2) {
            arg.push(b'"');
            remaining = &remaining[1..];
            return remaining;
        }
    } else {
        arg.extend(std::iter::repeat_n(b'\\', count));
    }

    remaining
}

fn winsplit<'a>(arena: &'a Bump, cmdline: &'a [u8]) -> Vec<&'a BStr> {
    let mut args = Vec::new();

    let save =
        |v: &mut Vec<u8>| -> &'a BStr { BStr::new(arena.alloc_slice_copy(&std::mem::take(v))) };

    let mut arg: Vec<u8> = Vec::new();
    let mut state = WinsplitState::Init;
    let mut remaining = cmdline;
    while !remaining.is_empty() {
        match state {
            WinsplitState::Init => {
                remaining = trim_ascii_space_or_null(remaining);
                if remaining.is_empty() {
                    break;
                }

                let (arg_slice, rem) =
                    split_once_exclusive(remaining, |b| is_special(*b)).unwrap_or((remaining, &[]));
                remaining = rem;

                let next_char = remaining.first().copied();
                if next_char.is_none_or(is_whitespace_or_null) {
                    args.push(BStr::new(arg_slice));
                    continue;
                }

                let next_char = next_char.unwrap_or_else(|| unreachable!());
                if next_char == b'"' {
                    remaining = &remaining[1..];
                    arg.extend_from_slice(arg_slice);
                    state = WinsplitState::InQuote;
                } else if next_char == b'\\' {
                    arg.extend_from_slice(arg_slice);
                    remaining = parse_backslash(remaining, &mut arg);
                    state = WinsplitState::NoQuote;
                }
            }
            WinsplitState::InQuote => {
                let (&ch, rem) = remaining
                    .split_first()
                    .unwrap_or_else(|| unreachable!("remaining should not be empty"));
                remaining = rem;

                if ch == b'"' {
                    if remaining.first() == Some(&b'"') {
                        arg.push(b'"');
                        remaining = &remaining[1..];
                    } else {
                        state = WinsplitState::NoQuote;
                    }
                } else if ch == b'\\' {
                    remaining = parse_backslash(remaining, &mut arg);
                } else {
                    arg.push(ch);
                }
            }
            WinsplitState::NoQuote => {
                let (&ch, rem) = remaining
                    .split_first()
                    .unwrap_or_else(|| unreachable!("remaining should not be empty"));
                remaining = rem;

                if is_whitespace_or_null(ch) {
                    args.push(save(&mut arg));
                    state = WinsplitState::Init;
                } else if ch == b'"' {
                    state = WinsplitState::InQuote;
                } else if ch == b'\\' {
                    remaining = parse_backslash(remaining, &mut arg);
                } else {
                    arg.push(ch);
                }
            }
        }
    }

    if state != WinsplitState::Init {
        args.push(save(&mut arg));
    }

    args
}

fn strip_prefix_ignore_ascii_case<'a>(v: &'a [u8], prefix: &[u8]) -> Option<&'a [u8]> {
    v.split_at_checked(prefix.len())
        .and_then(|(pre, remaining)| {
            if prefix.eq_ignore_ascii_case(pre) {
                Some(remaining)
            } else {
                None
            }
        })
}

fn parse_directive_data<'a>(
    arena: &'a Bump,
    data: &'a [u8],
) -> anyhow::Result<Vec<LinkerDirective<'a>>> {
    let mut parsed = Vec::new();

    let is_flag_char = |b: u8| b == b'/' || b == b'-';

    for arg in winsplit(arena, data) {
        if let Some(arg) = arg
            .first()
            .and_then(|b| is_flag_char(*b).then_some(&arg[1..]))
            && let Some(v) = strip_prefix_ignore_ascii_case(arg, b"defaultlib:")
        {
            parsed.push(LinkerDirective::Defaultlib(BStr::new(v)));
            continue;
        }
        parsed.push(LinkerDirective::Other(arg));
    }
    Ok(parsed)
}

/// Parses the .drectve section inside the COFF.
///
/// Returns an empty `Vec` if the COFF does not contain a `.drectve` section.
pub fn parse_linker_directives<'a>(
    arena: &'a Bump,
    coff: &CoffFile<'a>,
) -> anyhow::Result<Vec<LinkerDirective<'a>>> {
    for section in coff.sections() {
        let flags = section
            .coff_section()
            .characteristics
            .get(object::LittleEndian);

        if (flags & IMAGE_SCN_LNK_INFO) != 0
            && section.name_bytes().is_ok_and(|name| name == b".drectve")
        {
            let data = section.data().context("reading .drectve section data")?;
            return parse_directive_data(arena, data);
        }
    }

    Ok(Vec::new())
}

#[cfg(test)]
mod tests {

    use bumpalo::Bump;

    use crate::directives::{LinkerDirective, parse_directive_data, winsplit};

    #[test]
    fn defaultlibs() {
        const INPUT: &[u8] =
            b"  /DEFAULTLIB:\"uuid.lib\" /defaultlib:\"uuid.lib\" /DEFAULTLIB:uuid.lib";
        let arena = Bump::new();

        let parsed = parse_directive_data(&arena, INPUT).expect("could not parse data");
        for d in parsed {
            assert_eq!(d, LinkerDirective::Defaultlib(b"uuid.lib".into()));
        }
    }

    #[test]
    fn empty_spaces() {
        const INPUT: &[u8] = b"   ";
        let arena = Bump::new();

        let parsed = parse_directive_data(&arena, INPUT).expect("could not parse data");
        assert!(parsed.is_empty());
    }

    #[test]
    fn winsplit_test() {
        const INPUT: &[u8] = b"/DEFAULTLIB:\"uuid.lib\" /DEFAULTLIB:\"uuid.lib\"";
        let arena = Bump::new();
        let parsed = winsplit(&arena, INPUT);
        for token in parsed {
            println!("{token}");
        }
    }
}
