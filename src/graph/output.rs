use std::{cell::OnceCell, collections::BTreeMap};

use anyhow::{anyhow, bail};
use indexmap::IndexMap;
use log::debug;
use object::{
    pe::{
        IMAGE_FILE_LINE_NUMS_STRIPPED, IMAGE_REL_AMD64_ADDR32, IMAGE_REL_AMD64_ADDR32NB,
        IMAGE_REL_AMD64_ADDR64, IMAGE_REL_AMD64_REL32, IMAGE_REL_AMD64_REL32_5,
        IMAGE_REL_AMD64_SECREL, IMAGE_REL_AMD64_SECTION, IMAGE_REL_I386_ABSOLUTE,
        IMAGE_REL_I386_DIR32, IMAGE_REL_I386_DIR32NB, IMAGE_REL_I386_REL32, IMAGE_REL_I386_SECREL,
        IMAGE_REL_I386_SECTION, IMAGE_SYM_CLASS_EXTERNAL, IMAGE_SYM_CLASS_STATIC,
        IMAGE_SYM_TYPE_NULL,
    },
    write::coff::{Relocation, Writer},
};

use crate::linker::LinkerTargetArch;

use super::{
    LinkGraphArena,
    node::{
        LibraryNode, SectionName, SectionNode, SectionNodeCharacteristics, SectionNodeData,
        SymbolNodeType,
    },
};

/// An output section for the [`OutputGraph`].
pub struct OutputSection<'arena, 'data> {
    /// The name of the output section
    pub name: SectionName<'arena>,

    /// The section characteristics
    pub characteristics: SectionNodeCharacteristics,

    /// The name of the output section in the COFF
    output_name: OnceCell<object::write::coff::Name>,

    /// The size of the data
    size_of_raw_data: u32,

    /// The pointer to the section data
    pointer_to_raw_data: u32,

    /// The number of relocations
    number_of_relocations: u32,

    /// The pointer to the relocation data
    pointer_to_relocations: u32,

    /// The list of nodes in this output section.
    pub nodes: Vec<&'arena SectionNode<'arena, 'data>>,
}

impl<'arena, 'data> OutputSection<'arena, 'data> {
    pub fn new(
        name: impl Into<SectionName<'arena>>,
        characteristics: SectionNodeCharacteristics,
        nodes: Vec<&'arena SectionNode<'arena, 'data>>,
    ) -> OutputSection<'arena, 'data> {
        let mut characteristics = characteristics.zero_align();
        characteristics.remove(
            SectionNodeCharacteristics::LnkComdat | SectionNodeCharacteristics::LnkNRelocOvfl,
        );
        Self {
            name: name.into(),
            characteristics,
            output_name: OnceCell::new(),
            size_of_raw_data: 0,
            pointer_to_raw_data: 0,
            number_of_relocations: 0,
            pointer_to_relocations: 0,
            nodes,
        }
    }
}

/// Graph for building the final COFF.
///
/// This contains an additional output map which maps the input sections from
/// the built link graph to the output sections.
pub struct OutputGraph<'arena, 'data> {
    /// Target architecture
    machine: LinkerTargetArch,

    /// The list of output sections.
    output_sections: Vec<OutputSection<'arena, 'data>>,

    /// The API library node
    api_node: Option<&'arena LibraryNode<'arena, 'data>>,

    /// The library nodes
    library_nodes: IndexMap<&'data str, &'arena LibraryNode<'arena, 'data>>,

    /// Graph arena allocator.
    arena: &'arena LinkGraphArena,
}

impl<'arena, 'data> OutputGraph<'arena, 'data> {
    pub fn new(
        machine: LinkerTargetArch,
        output_sections: Vec<OutputSection<'arena, 'data>>,
        api_node: Option<&'arena LibraryNode<'arena, 'data>>,
        library_nodes: IndexMap<&'data str, &'arena LibraryNode<'arena, 'data>>,
        arena: &'arena LinkGraphArena,
    ) -> OutputGraph<'arena, 'data> {
        Self {
            machine,
            output_sections,
            api_node,
            library_nodes,
            arena,
        }
    }

    /// Builds the output COFF
    pub fn build_output(mut self) -> anyhow::Result<Vec<u8>> {
        let mut built_coff = Vec::new();
        let mut coff_writer = Writer::new(&mut built_coff);

        coff_writer.reserve_file_header();

        // Reserve section headers
        coff_writer.reserve_section_headers(self.output_sections.len().try_into().unwrap());

        for output_section in self.output_sections.iter_mut() {
            let mut section_alignment = 0u32;

            output_section
                .output_name
                .set(coff_writer.add_name(output_section.name.as_str().as_bytes()))
                .unwrap_or_else(|_| unreachable!());

            // Assign virtual addresses to each section
            for node in &output_section.nodes {
                if let Some(align) = node.characteristics().alignment() {
                    let align = align as u32;
                    output_section.size_of_raw_data =
                        output_section.size_of_raw_data.next_multiple_of(align);
                    section_alignment = section_alignment.max(align);
                }

                debug!(
                    "{}: mapping section '{}' to '{}' at address {:#x} with size {:#x}",
                    node.coff(),
                    node.name(),
                    output_section.name,
                    output_section.size_of_raw_data,
                    node.data().len(),
                );

                node.assign_virtual_address(output_section.size_of_raw_data);
                output_section.size_of_raw_data += node.data().len() as u32;
            }

            // Set the alignment needed for the output section
            output_section
                .characteristics
                .set_alignment(section_alignment);
        }

        // Reserve section data
        for section in self.output_sections.iter_mut() {
            if !section
                .characteristics
                .contains(SectionNodeCharacteristics::CntUninitializedData)
                && section.size_of_raw_data > 0
            {
                section.pointer_to_raw_data =
                    coff_writer.reserve_section(section.size_of_raw_data as usize);
            }
        }

        let mut local_undefined = IndexMap::new();

        // Reserve relocations skipping relocations to the same output section
        for output_section in self.output_sections.iter_mut() {
            for &section_node in &output_section.nodes {
                let mut pending_relocs = 0;

                section_node.relocations().try_retain(|reloc| {
                    let symbol = reloc.target();

                    // Discard definition edges to unused sections
                    let mut has_discards = false;
                    symbol.definitions().retain(|definition| {
                        has_discards |= definition.target().is_discarded();
                        !definition.target().is_discarded()
                    });

                    // Select the definition that should be used
                    let selected = symbol
                        .definitions()
                        .iter()
                        .chain(symbol.weak_default_definitions())
                        .find(|definition| !definition.target().is_discarded());

                    if let Some(selected) = selected {
                        // Record this relocation as pending if it is a relative
                        // relocation to the same output section
                        if !reloc.weight().is_vabased(self.machine) {
                            let is_intrasection =
                                output_section.nodes.iter().any(|&check_section| {
                                    std::ptr::eq(check_section, selected.target())
                                });

                            if is_intrasection {
                                pending_relocs += 1;
                            }
                        }

                        return Ok(true);
                    } else if !symbol.imports().is_empty() {
                        return Ok(true);
                    } else if !has_discards {
                        local_undefined.insert(symbol.name().as_str(), symbol);
                        return Ok(true);
                    }

                    // Symbol has no imports and all definitions are in
                    // discarded sections. Return an error.
                    let sorted_definitions = section_node
                        .definitions()
                        .iter()
                        .filter_map(|definition| {
                            let symbol = definition.source();
                            if symbol.is_section_symbol() || symbol.is_label() {
                                None
                            } else {
                                Some((definition.weight().address(), symbol.name()))
                            }
                        })
                        .collect::<BTreeMap<_, _>>();

                    let reference_symbol = sorted_definitions.range(0..=reloc.weight().address())
                        .next_back()
                        .map(|(_, name)| name.demangle().to_string())
                        .unwrap_or_else(|| {
                                format!("{}+{:#x}", section_node.name(), reloc.weight().address())
                        });

                    bail!("{}: {reference_symbol} references symbol '{}' defined in discarded section", section_node.coff(), symbol.name().demangle());
                })?;

                let kept_relocs = section_node.relocations().len() - pending_relocs;
                output_section.number_of_relocations += u32::try_from(kept_relocs).unwrap();
            }

            output_section.pointer_to_relocations =
                coff_writer.reserve_relocations(output_section.number_of_relocations as usize);
        }

        // Reserve symbols defined in sections
        for section in self.output_sections.iter() {
            // Reserve the section symbol
            let section_symbol_index = coff_writer.reserve_symbol_index();
            let _ = coff_writer.reserve_aux_section();

            for section_node in &section.nodes {
                // Assign table indicies to defined symbols
                for definition in section_node.definitions() {
                    let symbol = definition.source();

                    // Section symbol already reserved. Set the index to the
                    // existing one
                    if symbol.is_section_symbol() {
                        symbol
                            .assign_table_index(section_symbol_index)
                            .unwrap_or_else(|v| {
                                panic!(
                                    "symbol {} already assigned to symbol table index {v}",
                                    symbol.name().demangle()
                                )
                            });
                    } else if symbol.is_label() {
                        // Associate labels with the section symbol
                        symbol
                            .assign_table_index(section_symbol_index)
                            .unwrap_or_else(|v| {
                                panic!(
                                    "symbol {} already assigned to symbol table index {v}",
                                    symbol.name().demangle()
                                )
                            });
                    } else {
                        let _ = symbol.output_name().get_or_init(|| {
                            coff_writer.add_name(symbol.name().as_str().as_bytes())
                        });

                        // Reserve an index for this symbol
                        symbol
                            .assign_table_index(coff_writer.reserve_symbol_index())
                            .unwrap_or_else(|v| {
                                panic!(
                                    "symbol {} already assigned to symbol table index {v}",
                                    symbol.name().demangle()
                                )
                            });
                    }
                }
            }
        }

        let mangling_prefix = if self.machine == LinkerTargetArch::I386 {
            "_"
        } else {
            ""
        };

        // Reserve API imported symbols
        if let Some(api_node) = self.api_node {
            for import in api_node.imports() {
                let symbol = import.source();

                let name = self.arena.alloc_str(&format!(
                    "__imp_{mangling_prefix}{symbol_name}",
                    symbol_name = import.weight().import_name(),
                ));

                let _ = symbol
                    .output_name()
                    .get_or_init(|| coff_writer.add_name(name.as_bytes()));

                symbol
                    .assign_table_index(coff_writer.reserve_symbol_index())
                    .unwrap_or_else(|v| {
                        panic!(
                            "symbol {} already assigned to symbol table index {v}",
                            symbol.name().demangle()
                        )
                    });
            }
        }

        // Reserve undefined symbols
        for symbol in local_undefined.values() {
            let _ = symbol
                .output_name()
                .get_or_init(|| coff_writer.add_name(symbol.name().as_str().as_bytes()));

            symbol
                .assign_table_index(coff_writer.reserve_symbol_index())
                .unwrap_or_else(|v| {
                    panic!(
                        "symbol {} already assigned to symbol table index {v}",
                        symbol.name().demangle()
                    )
                });
        }

        // Reserve library imported symbols
        for library in self.library_nodes.values() {
            for import in library.imports() {
                let symbol = import.source();

                let name = self.arena.alloc_str(&format!(
                    "__imp_{mangling_prefix}{library_name}${symbol_name}",
                    mangling_prefix = if self.machine == LinkerTargetArch::I386 {
                        "_"
                    } else {
                        ""
                    },
                    library_name = library.name().trim_dll_suffix(),
                    symbol_name = import.weight().import_name(),
                ));

                let _ = symbol
                    .output_name()
                    .get_or_init(|| coff_writer.add_name(name.as_bytes()));

                symbol
                    .assign_table_index(coff_writer.reserve_symbol_index())
                    .unwrap_or_else(|v| {
                        panic!(
                            "symbol {} already assigned to symbol table index {v}",
                            symbol.name().demangle()
                        )
                    });
            }
        }

        // Finish reserving COFF data
        coff_writer.reserve_symtab_strtab();

        // Write out the file header
        coff_writer
            .write_file_header(object::write::coff::FileHeader {
                machine: self.machine.into(),
                time_date_stamp: 0,
                characteristics: IMAGE_FILE_LINE_NUMS_STRIPPED,
            })
            .unwrap();

        // Write out the section headers
        for output_section in &self.output_sections {
            coff_writer.write_section_header(object::write::coff::SectionHeader {
                name: *output_section.output_name.get().unwrap_or_else(|| {
                    panic!(
                        "Output section name for {} never reserved in COFF",
                        output_section.name
                    )
                }),
                size_of_raw_data: output_section.size_of_raw_data,
                pointer_to_raw_data: output_section.pointer_to_raw_data,
                characteristics: output_section.characteristics.bits(),
                pointer_to_relocations: output_section.pointer_to_relocations,
                number_of_relocations: output_section.number_of_relocations,
                ..Default::default()
            });
        }

        // Write out the section data
        for section in &self.output_sections {
            if section.size_of_raw_data > 0
                && !section
                    .characteristics
                    .contains(SectionNodeCharacteristics::CntUninitializedData)
            {
                coff_writer.write_section_align();

                let alignment_byte = if section
                    .characteristics
                    .contains(SectionNodeCharacteristics::CntCode)
                {
                    0x90u8
                } else {
                    0x00u8
                };

                let mut data_written = 0;
                let mut alignment_buffer = vec![alignment_byte; 16];

                for node in section.nodes.iter() {
                    // Write alignment padding
                    let needed = node.virtual_address() - data_written;
                    if needed > 0 {
                        alignment_buffer.resize(needed as usize, alignment_byte);
                        coff_writer.write(&alignment_buffer);
                        data_written += needed;
                    }

                    let section_data = match node.data() {
                        SectionNodeData::Initialized(data) => data,
                        SectionNodeData::Uninitialized(size) => {
                            // This node contains uninitialized data but the
                            // output section should be initialized.
                            // Write out padding bytes to satisfy the size
                            // requested
                            alignment_buffer.resize(size as usize, alignment_byte);
                            alignment_buffer.as_slice()
                        }
                    };

                    coff_writer.write(section_data);
                    data_written += section_data.len() as u32;
                }
            }
        }

        // Write out the relocations
        for output_section in &self.output_sections {
            for &section_node in &output_section.nodes {
                for reloc in section_node.relocations() {
                    let target_symbol = reloc.target();
                    let mut linked_symbol = reloc.target();
                    let definition = linked_symbol.definitions().front().or_else(|| {
                        target_symbol
                            .weak_default_definitions()
                            .find(|definition| !definition.target().is_discarded())
                    });

                    if let Some(definition) = definition {
                        linked_symbol = definition.source();

                        let is_intrasection = || {
                            output_section.nodes.iter().any(|&check_section| {
                                std::ptr::eq(check_section, definition.target())
                            })
                        };

                        if !reloc.weight().is_vabased(self.machine) && is_intrasection() {
                            continue;
                        }
                    }

                    coff_writer.write_relocation(Relocation {
                        virtual_address: section_node.virtual_address() + reloc.weight().address(),
                        symbol: linked_symbol.table_index().unwrap_or_else(|| {
                            panic!(
                                "symbol {} was never assigned a symbol table index",
                                linked_symbol.name().demangle()
                            )
                        }),
                        typ: reloc.weight().typ(),
                    });
                }
            }
        }

        // Write out symbols defined in sections
        for (section_index, output_section) in self.output_sections.iter().enumerate() {
            // Write the section symbol
            coff_writer.write_symbol(object::write::coff::Symbol {
                name: *output_section.output_name.get().unwrap_or_else(|| {
                    panic!(
                        "Output section name {} never reserved in COFF",
                        output_section.name
                    )
                }),
                value: 0,
                section_number: (section_index + 1).try_into().unwrap(),
                typ: IMAGE_SYM_TYPE_NULL,
                storage_class: IMAGE_SYM_CLASS_STATIC,
                number_of_aux_symbols: 1,
            });

            coff_writer.write_aux_section(object::write::coff::AuxSymbolSection {
                length: output_section.size_of_raw_data,
                number_of_relocations: output_section.number_of_relocations,
                number_of_linenumbers: 0,
                // The object crate will calculate the checksum
                check_sum: 0,
                number: (section_index + 1).try_into().unwrap(),
                selection: 0,
            });

            for section_node in &output_section.nodes {
                for definition in section_node.definitions() {
                    let symbol = definition.source();

                    // Skip labels and section symbols
                    if !symbol.is_section_symbol() && !symbol.is_label() {
                        coff_writer.write_symbol(object::write::coff::Symbol {
                            name: symbol.output_name().get().copied().unwrap_or_else(|| {
                                panic!(
                                    "symbol {} never had the name reserved in the output COFF",
                                    symbol.name().demangle()
                                )
                            }),
                            value: definition.weight().address() + section_node.virtual_address(),
                            section_number: (section_index + 1).try_into().unwrap(),
                            typ: match symbol.typ() {
                                SymbolNodeType::Value(typ) => typ,
                                _ => unreachable!(),
                            },
                            storage_class: symbol.storage_class().into(),
                            number_of_aux_symbols: 0,
                        });
                    }
                }
            }
        }

        // Write out API imported symbols
        if let Some(api_node) = self.api_node {
            for import in api_node.imports() {
                let symbol = import.source();
                coff_writer.write_symbol(object::write::coff::Symbol {
                    name: symbol.output_name().get().copied().unwrap_or_else(|| {
                        panic!(
                            "symbol {} never had the name reserved in the output COFF",
                            symbol.name().demangle()
                        )
                    }),
                    value: 0,
                    section_number: 0,
                    typ: 0,
                    storage_class: IMAGE_SYM_CLASS_EXTERNAL,
                    number_of_aux_symbols: 0,
                });
            }
        }

        // Write out local undefined symbols
        for symbol in local_undefined.values() {
            coff_writer.write_symbol(object::write::coff::Symbol {
                name: symbol.output_name().get().copied().unwrap_or_else(|| {
                    panic!(
                        "symbol {} never had the name reserved in the output COFF",
                        symbol.name().demangle()
                    )
                }),
                value: 0,
                section_number: 0,
                typ: 0,
                storage_class: IMAGE_SYM_CLASS_EXTERNAL,
                number_of_aux_symbols: 0,
            });
        }

        // Write out library imported symbols
        for library in self.library_nodes.values() {
            for import in library.imports() {
                let symbol = import.source();
                coff_writer.write_symbol(object::write::coff::Symbol {
                    name: symbol.output_name().get().copied().unwrap_or_else(|| {
                        panic!(
                            "symbol {} never had the name reserved in the output COFF",
                            symbol.name().demangle()
                        )
                    }),
                    value: 0,
                    section_number: 0,
                    typ: 0,
                    storage_class: IMAGE_SYM_CLASS_EXTERNAL,
                    number_of_aux_symbols: 0,
                });
            }
        }

        // Finish writing the COFF
        coff_writer.write_strtab();

        // Fixup relocations
        for output_section in &self.output_sections {
            // Skip output sections that do not contain any data
            if output_section.pointer_to_raw_data == 0 || output_section.size_of_raw_data == 0 {
                continue;
            }

            let section_data_base = output_section.pointer_to_raw_data as usize;
            let data_range =
                section_data_base..section_data_base + output_section.size_of_raw_data as usize;
            let section_data = &mut built_coff[data_range];

            for &section_node in &output_section.nodes {
                for reloc_edge in section_node.relocations() {
                    let target_symbol = reloc_edge.target();
                    let definition = target_symbol.definitions().front().or_else(|| {
                        target_symbol
                            .weak_default_definitions()
                            .find(|definition| !definition.target().is_discarded())
                    });

                    let Some(definition) = definition else {
                        continue;
                    };

                    let target_symbol = definition.source();
                    let target_section = definition.target();
                    let reloc = reloc_edge.weight();
                    let reloc_addr = section_node.virtual_address() + reloc.address();
                    let target_addr = definition.weight().address() as u64
                        + target_section.virtual_address() as u64;

                    let reloc_bounds_error = || {
                        anyhow!(
                            "{}: {}+{:#x} relocation is outside of section bounds (size = {:#x})",
                            section_node.coff(),
                            section_node.name(),
                            reloc.address(),
                            section_node.data().len()
                        )
                    };

                    let reloc_overflow_error = || {
                        anyhow!(
                            "{}: relocation adjustment at '{}+{:#x}' overflowed",
                            section_node.coff(),
                            section_node.name(),
                            reloc.address(),
                        )
                    };

                    let read32le = |data: &[u8]| -> anyhow::Result<u32> {
                        type V = u32;
                        data.get(..std::mem::size_of::<V>())
                            .map(|data| {
                                <[u8; std::mem::size_of::<V>()]>::try_from(data)
                                    .unwrap_or_else(|_| unreachable!())
                            })
                            .map(V::from_le_bytes)
                            .ok_or_else(reloc_bounds_error)
                    };

                    let read64le = |data: &[u8]| {
                        type V = u64;
                        data.get(..std::mem::size_of::<V>())
                            .map(|data| {
                                <[u8; std::mem::size_of::<V>()]>::try_from(data)
                                    .unwrap_or_else(|_| unreachable!())
                            })
                            .map(V::from_le_bytes)
                            .ok_or_else(reloc_bounds_error)
                    };

                    let write32le = |data: &mut [u8], val: u32| {
                        type V = u32;
                        data.get_mut(..std::mem::size_of::<V>())
                            .ok_or_else(reloc_bounds_error)?
                            .copy_from_slice(&val.to_le_bytes());
                        Ok(())
                    };

                    let write64le = |data: &mut [u8], val: u64| {
                        type V = u64;
                        data.get_mut(..std::mem::size_of::<V>())
                            .ok_or_else(reloc_bounds_error)?
                            .copy_from_slice(&val.to_le_bytes());
                        Ok(())
                    };

                    let add32 = |data: &mut [u8], amt| -> anyhow::Result<()> {
                        write32le(
                            data,
                            read32le(data)?
                                .checked_add(amt)
                                .ok_or_else(reloc_overflow_error)?,
                        )
                    };

                    let add64 = |data: &mut [u8], amt| -> anyhow::Result<()> {
                        write64le(
                            data,
                            read64le(data)?
                                .checked_add(amt)
                                .ok_or_else(reloc_overflow_error)?,
                        )
                    };

                    let unsupported_relocation_error = |typ: u16| {
                        anyhow!(
                            "{}: unsupported relocation type '{typ:#x}' at '{}+{:#x}",
                            section_node.coff(),
                            section_node.name(),
                            reloc.address(),
                        )
                    };

                    let apply_amd64_rel = |data, typ, address: u64, target: u64, base: u64| {
                        match typ {
                            IMAGE_REL_AMD64_ADDR32 => {
                                add32(data, target as u32 + base as u32)?;
                            }
                            IMAGE_REL_AMD64_ADDR64 => {
                                add64(data, target + base)?;
                            }
                            IMAGE_REL_AMD64_ADDR32NB => {
                                add32(data, target as u32)?;
                            }
                            IMAGE_REL_AMD64_REL32..=IMAGE_REL_AMD64_REL32_5 => {
                                let addend = typ;
                                add32(
                                    data,
                                    target.wrapping_sub(address).wrapping_sub(addend.into()) as u32,
                                )?;
                            }
                            IMAGE_REL_AMD64_SECTION | IMAGE_REL_AMD64_SECREL => {
                                // These types of relocations do not make sense
                                // to process since debug info is not supported
                            }
                            _ => {
                                return Err(unsupported_relocation_error(typ));
                            }
                        }
                        Ok(())
                    };

                    let apply_i386_rel = |data, typ, address: u32, target: u32, base: u32| {
                        match typ {
                            IMAGE_REL_I386_ABSOLUTE => (),
                            IMAGE_REL_I386_DIR32 => {
                                add32(data, target + base)?;
                            }
                            IMAGE_REL_I386_DIR32NB => {
                                add32(data, target)?;
                            }
                            IMAGE_REL_I386_REL32 => {
                                add32(data, target - address - 4)?;
                            }
                            IMAGE_REL_I386_SECTION | IMAGE_REL_I386_SECREL => {
                                // These types of relocations do not make sense
                                // to process since debug info is not supported
                            }
                            _ => {
                                return Err(unsupported_relocation_error(typ));
                            }
                        }
                        Ok(())
                    };

                    let reloc_data = section_data
                        .get_mut(reloc_addr as usize..)
                        .ok_or_else(reloc_bounds_error)?;

                    // If the relocation is relative to a symbol defined in
                    // the same section, fully apply it.
                    // If the relocation not symbolic, adjust it by the amount
                    // that the target symbol has shifted
                    let is_intrasection = || {
                        output_section
                            .nodes
                            .iter()
                            .any(|&check_section| std::ptr::eq(check_section, target_section))
                    };

                    if !reloc.is_vabased(self.machine) && is_intrasection() {
                        if self.machine == LinkerTargetArch::Amd64 {
                            apply_amd64_rel(
                                reloc_data,
                                reloc.typ(),
                                reloc_addr as u64,
                                target_addr,
                                0,
                            )?;
                        } else {
                            apply_i386_rel(
                                reloc_data,
                                reloc.typ(),
                                reloc_addr,
                                target_addr as u32,
                                0,
                            )?;
                        }
                    } else if target_symbol.is_section_symbol() || target_symbol.is_label() {
                        if self.machine == LinkerTargetArch::Amd64
                            && reloc.typ() == IMAGE_REL_AMD64_ADDR64
                        {
                            add64(reloc_data, target_addr)?;
                        } else {
                            add32(reloc_data, target_addr as u32)?;
                        }
                    }
                }
            }
        }

        Ok(built_coff)
    }
}
