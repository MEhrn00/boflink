use std::{cell::OnceCell, collections::BTreeMap};

use indexmap::IndexMap;
use log::debug;
use object::{
    pe::{
        IMAGE_FILE_LINE_NUMS_STRIPPED, IMAGE_SYM_CLASS_EXTERNAL, IMAGE_SYM_CLASS_STATIC,
        IMAGE_SYM_TYPE_NULL,
    },
    write::coff::{Relocation, Writer},
};

use crate::linker::LinkerTargetArch;

use super::{
    LinkGraphArena, LinkGraphLinkError,
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
    pub fn build_output(mut self) -> Result<Vec<u8>, LinkGraphLinkError> {
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
            let mut reloc_count = 0usize;

            for section_node in &output_section.nodes {
                'next_reloc: for reloc in section_node.relocations() {
                    let symbol = reloc.target();
                    let mut definition_count = 0usize;

                    for definition in symbol
                        .definitions()
                        .iter()
                        .chain(symbol.weak_default_definitions())
                    {
                        definition_count += 1;

                        if definition.target().is_discarded() {
                            continue;
                        }

                        let target_section = definition.target();
                        if !output_section
                            .nodes
                            .iter()
                            .any(|section| std::ptr::eq(*section, target_section))
                        {
                            reloc_count += 1;
                        }

                        continue 'next_reloc;
                    }

                    // Relocation to an imported or undefined symbol.
                    if !symbol.imports().is_empty() || definition_count == 0 {
                        // Local undefined symbol
                        if symbol.imports().is_empty() {
                            local_undefined.insert(symbol.name().as_str(), symbol);
                        }

                        reloc_count += 1;
                        continue;
                    }

                    // Symbol has no imports and all definitions are in
                    // discarded sections. Return an error.

                    let coff_name = section_node.coff().to_string();

                    let symbol_defs = BTreeMap::from_iter(
                        section_node.definitions().iter().filter_map(|definition| {
                            let ref_symbol = definition.source();
                            if ref_symbol.is_section_symbol() || ref_symbol.is_label() {
                                None
                            } else {
                                Some((definition.weight().address(), ref_symbol.name()))
                            }
                        }),
                    );

                    if let Some(reference_symbol) =
                        symbol_defs.range(0..=reloc.weight().address()).next_back()
                    {
                        return Err(LinkGraphLinkError::DiscardedSection {
                            coff_name,
                            reference: reference_symbol.1.demangle().to_string(),
                            symbol: symbol.name().demangle().to_string(),
                        });
                    }

                    return Err(LinkGraphLinkError::DiscardedSection {
                        coff_name,
                        reference: format!(
                            "{}+{:#x}",
                            section_node.name(),
                            reloc.weight().address()
                        ),
                        symbol: symbol.name().demangle().to_string(),
                    });
                }
            }

            output_section.number_of_relocations = reloc_count.try_into().unwrap();
            output_section.pointer_to_relocations = coff_writer.reserve_relocations(reloc_count);
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

        // Reserve API imported symbols
        if let Some(api_node) = self.api_node {
            for import in api_node.imports() {
                let symbol = import.source();

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
                    "__imp_{}${}",
                    library.name().trim_dll_suffix(),
                    import.weight().import_name()
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

        // Write out the relocations skipping relocations to the same section
        for output_section in &self.output_sections {
            for section_node in &output_section.nodes {
                for reloc in section_node.relocations() {
                    let target_symbol = reloc.target();
                    let mut linked_symbol = target_symbol;

                    if let Some(definition) = target_symbol
                        .definitions()
                        .iter()
                        .chain(target_symbol.weak_default_definitions())
                        .find(|definition| !definition.target().is_discarded())
                    {
                        if output_section
                            .nodes
                            .iter()
                            .any(|section| std::ptr::eq(*section, definition.target()))
                        {
                            continue;
                        }

                        linked_symbol = definition.source();
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

            for section_node in &output_section.nodes {
                let section_data_ptr = section_data_base + section_node.virtual_address() as usize;

                let section_data =
                    &mut built_coff[section_data_ptr..section_data_ptr + section_node.data().len()];

                for reloc_edge in section_node.relocations() {
                    let target_symbol = reloc_edge.target();

                    let symbol_definition = match target_symbol
                        .definitions()
                        .iter()
                        .chain(target_symbol.weak_default_definitions())
                        .find(|definition| !definition.target().is_discarded())
                    {
                        Some(definition) => definition,
                        None => continue,
                    };

                    let target_section = symbol_definition.target();
                    let reloc = reloc_edge.weight();

                    // Return an error if the relocation is out of bounds.
                    if reloc.virtual_address + 4 > section_node.data().len() as u32 {
                        return Err(LinkGraphLinkError::RelocationBounds {
                            coff_name: section_node.coff().to_string(),
                            section: section_node.name().to_string(),
                            address: reloc.virtual_address,
                            size: section_node.data().len() as u32,
                        });
                    }

                    // The relocation bounds check above checks the relocation
                    // in the graph. This indexes into the built COFF after
                    // everything is merged. The slice index should always
                    // be in bounds but if it is not, there is some logic
                    // error above. Panic with a verbose error message if that
                    // is the case.

                    let reloc_data: [u8; 4] = section_data
                        .get(reloc.address() as usize..reloc.address() as usize + 4)
                        .map(|data| data.try_into().unwrap_or_else(|_| unreachable!()))
                        .unwrap_or_else(|| {
                            unreachable!(
                                "relocation in section '{}' is out of bounds",
                                section_node.name()
                            )
                        });

                    // Update relocations
                    let relocated_val = if target_symbol.is_section_symbol()
                        && !output_section
                            .nodes
                            .iter()
                            .any(|section| std::ptr::eq(*section, target_section))
                    {
                        // Target symbol is a section symbol. Relocations need to
                        // be adjusted to account for the section shift.
                        let reloc_val = u32::from_le_bytes(reloc_data);

                        reloc_val
                            .checked_add(target_section.virtual_address())
                            .ok_or_else(|| LinkGraphLinkError::RelocationOverflow {
                                coff_name: section_node.coff().to_string(),
                                section: section_node.name().to_string(),
                                address: reloc.address(),
                            })?
                    } else if section_node.name().group_name() == target_section.name().group_name()
                    {
                        // Relocation targets a symbol defined in the same section.
                        // Apply the relocation to the symbol address.

                        let reloc_addr = reloc.address() + section_node.virtual_address();
                        let symbol_addr =
                            symbol_definition.weight().address() + target_section.virtual_address();

                        let reloc_val = u32::from_be_bytes(reloc_data);
                        let delta = symbol_addr.wrapping_sub(reloc_addr + 4);
                        reloc_val.wrapping_add(delta)
                    } else if target_symbol.is_label() {
                        // Old relocation target symbol is a label. The current
                        // relocation points to the section symbol and the label
                        // was discarded.
                        // Handle this like a section symbol relocation but
                        // shift it to point to the label's virtual address in
                        // the section.
                        let reloc_val = u32::from_le_bytes(reloc_data);
                        let symbol_addr = symbol_definition.weight().address();

                        reloc_val
                            .checked_add(target_section.virtual_address())
                            .and_then(|reloc_val| reloc_val.checked_add(symbol_addr))
                            .ok_or_else(|| LinkGraphLinkError::RelocationOverflow {
                                coff_name: section_node.coff().to_string(),
                                section: section_node.name().to_string(),
                                address: reloc.address(),
                            })?
                    } else {
                        // Relocation target is symbolic and does not need
                        // updating
                        continue;
                    };

                    // Write the new reloc
                    section_data[reloc.address() as usize..reloc.address() as usize + 4]
                        .copy_from_slice(&relocated_val.to_le_bytes());
                }
            }
        }

        Ok(built_coff)
    }
}
