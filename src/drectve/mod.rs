use object::{Object, ObjectSection, coff::CoffFile, pe::IMAGE_SCN_LNK_INFO};

use parsers::{Parser, many0, many1, not_token, token};

mod parsers;

pub struct DrectveLibraries<'a> {
    section_data: &'a str,
}

impl<'a> DrectveLibraries<'a> {
    fn parse(data: &'a str) -> DrectveLibraries<'a> {
        Self { section_data: data }
    }
}

impl<'a> Iterator for DrectveLibraries<'a> {
    type Item = &'a str;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let ((flag, value), remaining) = many0(token(" "))
                .preceeds(token("-").or(token("/")))
                .preceeds(
                    many1(not_token(":")).terminated_by(token(":")).then(
                        many1(not_token("\""))
                            .surrounded_by(token("\""))
                            .or(many1(not_token(" ")))
                            .terminated_by(token(" ")),
                    ),
                )
                .parse(self.section_data)
                .ok()?;

            self.section_data = remaining;

            if flag.eq_ignore_ascii_case("DEFAULTLIB") {
                return Some(value);
            }
        }
    }
}

pub fn parse_drectve_libraries<'a>(coff: &CoffFile<'a>) -> Option<DrectveLibraries<'a>> {
    let drectve_section = coff.section_by_name(".drectve")?;
    if drectve_section
        .coff_section()
        .characteristics
        .get(object::LittleEndian)
        & IMAGE_SCN_LNK_INFO
        == 0
    {
        return None;
    }

    let section_data = drectve_section.data().ok()?;
    if section_data
        .get(..3)
        .is_some_and(|prefix| prefix == [0xef, 0xbb, 0xbf])
    {
        Some(DrectveLibraries::parse(
            std::str::from_utf8(section_data.get(3..)?).ok()?,
        ))
    } else {
        Some(DrectveLibraries::parse(
            std::str::from_utf8(section_data).ok()?,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::DrectveLibraries;

    #[test]
    fn quoted() {
        const INPUT: &str =
            "  /DEFAULTLIB:\"uuid.lib\" /DEFAULTLIB:\"advapi32.lib\" /DEFAULTLIB:\"OLDNAMES\" ";

        const LIBRARIES: [&str; 3] = ["uuid.lib", "advapi32.lib", "OLDNAMES"];

        let parsed = DrectveLibraries::parse(INPUT).collect::<Vec<_>>();
        for library in LIBRARIES {
            assert!(
                parsed.contains(&library),
                "Could not find {library} in {parsed:?}",
            );
        }
    }

    #[test]
    fn unquoted() {
        const INPUT: &str = "  /DEFAULTLIB:uuid.lib /DEFAULTLIB:advapi32.lib /DEFAULTLIB:OLDNAMES ";

        const LIBRARIES: [&str; 3] = ["uuid.lib", "advapi32.lib", "OLDNAMES"];

        let parsed = DrectveLibraries::parse(INPUT).collect::<Vec<_>>();
        for library in LIBRARIES {
            assert!(
                parsed.contains(&library),
                "Could not find {library} in {parsed:?}",
            );
        }
    }

    #[test]
    fn mixed() {
        const INPUT: &str =
            "  /DEFAULTLIB:uuid.lib /DEFAULTLIB:\"advapi32.lib\" /DEFAULTLIB:OLDNAMES ";

        const LIBRARIES: [&str; 3] = ["uuid.lib", "advapi32.lib", "OLDNAMES"];
        let parsed = DrectveLibraries::parse(INPUT).collect::<Vec<_>>();
        for library in LIBRARIES {
            assert!(
                parsed.contains(&library),
                "Could not find {library} in {parsed:?}",
            );
        }
    }
}
