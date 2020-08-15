// SPDX-License-Identifier: GPL-2.0-only
// (c) William Fonkou Tambe

#include "sysdep.h"
#include "bfd.h"
#include "libbfd.h"
#include "elf-bfd.h"
#include "elf/pu32.h"

static reloc_howto_type pu32_elf_howto_table [] = {
	// This reloc does nothing.
	HOWTO (R_PU32_NONE,             // type
		0,                      // rightshift
		0,                      // size (0 = byte, 1 = short, 2 = long)
		32,                     // bitsize
		false,                  // pc_relative
		0,                      // bitpos
		complain_overflow_dont, // complain_on_overflow
		bfd_elf_generic_reloc,  // special_function
		"R_PU32_NONE",          // name
		false,                  // partial_inplace
		0,                      // src_mask
		0,                      // dst_mask
		false),                 // pcrel_offset

	// 8 bits relocation.
	HOWTO (R_PU32_8,                // type
		0,                      // rightshift
		1,                      // size (0 = byte, 1 = short, 2 = long)
		8,                      // bitsize
		false,                  // pc_relative
		0,                      // bitpos
		complain_overflow_bitfield, // complain_on_overflow
		bfd_elf_generic_reloc,  // special_function
		"R_PU32_8",             // name
		false,                  // partial_inplace
		0x0000,                 // src_mask
		0x0f0f,                 // dst_mask
		false),                 // pcrel_offset

	// 16 bits relocation.
	HOWTO (R_PU32_16,               // type
		0,                      // rightshift
		1,                      // size (0 = byte, 1 = short, 2 = long)
		16,                     // bitsize
		false,                  // pc_relative
		0,                      // bitpos
		complain_overflow_bitfield, // complain_on_overflow
		bfd_elf_generic_reloc,  // special_function
		"R_PU32_16",            // name
		false,                  // partial_inplace
		0x0000,                 // src_mask
		0xffff,                 // dst_mask
		false),                 // pcrel_offset

	// A 32 bits relocation.
	HOWTO (R_PU32_32,               // type
		0,                      // rightshift
		2,                      // size (0 = byte, 1 = short, 2 = long)
		32,                     // bitsize
		false,                  // pc_relative
		0,                      // bitpos
		complain_overflow_bitfield, // complain_on_overflow
		bfd_elf_generic_reloc,  // special_function
		"R_PU32_32",            // name
		false,                  // partial_inplace
		0x00000000,             // src_mask
		0xffffffff,             // dst_mask
		false),                 // pcrel_offset

	// 8 bits relocation.
	HOWTO (R_PU32_8_PCREL,          // type
		0,                      // rightshift
		1,                      // size (0 = byte, 1 = short, 2 = long)
		8,                      // bitsize
		true,                   // pc_relative
		0,                      // bitpos
		complain_overflow_bitfield, // complain_on_overflow
		bfd_elf_generic_reloc,  // special_function
		"R_PU32_8_PCREL",       // name
		false,                  // partial_inplace
		0x0000,                 // src_mask
		0x0f0f,                 // dst_mask
		true),                  // pcrel_offset

	// 16 bits relocation.
	HOWTO (R_PU32_16_PCREL,         // type
		0,                      // rightshift
		1,                      // size (0 = byte, 1 = short, 2 = long)
		16,                     // bitsize
		true,                   // pc_relative
		0,                      // bitpos
		complain_overflow_bitfield, // complain_on_overflow
		bfd_elf_generic_reloc,  // special_function
		"R_PU32_16_PCREL",      // name
		false,                  // partial_inplace
		0x0000,                 // src_mask
		0xffff,                 // dst_mask
		true),                  // pcrel_offset

	// A 32 bits relocation.
	HOWTO (R_PU32_32_PCREL,         // type
		0,                      // rightshift
		2,                      // size (0 = byte, 1 = short, 2 = long)
		32,                     // bitsize
		true,                   // pc_relative
		0,                      // bitpos
		complain_overflow_bitfield, // complain_on_overflow
		bfd_elf_generic_reloc,  // special_function
		"R_PU32_32_PCREL",      // name
		false,                  // partial_inplace
		0x00000000,             // src_mask
		0xffffffff,             // dst_mask
		true),                  // pcrel_offset
};

struct pu32_reloc_map {
	bfd_reloc_code_real_type bfd_reloc_val;
	unsigned int pu32_reloc_val;
};

static const struct pu32_reloc_map pu32_reloc_map [] = {
	{ BFD_RELOC_NONE,     R_PU32_NONE },
	{ BFD_RELOC_8,        R_PU32_8 },
	{ BFD_RELOC_16,       R_PU32_16 },
	{ BFD_RELOC_32,       R_PU32_32 },
	{ BFD_RELOC_8_PCREL,  R_PU32_8_PCREL },
	{ BFD_RELOC_16_PCREL, R_PU32_16_PCREL },
	{ BFD_RELOC_32_PCREL, R_PU32_32_PCREL },
};

static reloc_howto_type *pu32_reloc_type_lookup (
	bfd *abfd ATTRIBUTE_UNUSED, bfd_reloc_code_real_type code) {
	for (unsigned i = (sizeof(pu32_reloc_map) / sizeof(pu32_reloc_map[0])); i--;)
		if (pu32_reloc_map [i].bfd_reloc_val == code)
			return & pu32_elf_howto_table[pu32_reloc_map[i].pu32_reloc_val];
	return NULL;
}

static reloc_howto_type *pu32_reloc_name_lookup (
	bfd *abfd ATTRIBUTE_UNUSED, const char *r_name) {
	for (unsigned i = 0; i < sizeof(pu32_elf_howto_table) / sizeof(pu32_elf_howto_table[0]); i++)
		if (pu32_elf_howto_table[i].name != NULL &&
			strcasecmp (pu32_elf_howto_table[i].name, r_name) == 0)
			return &pu32_elf_howto_table[i];
	return NULL;
}

static bool pu32_info_to_howto_rela (
	bfd *abfd, arelent *cache_ptr,
	Elf_Internal_Rela *dst) {

	unsigned int r_type = ELF32_R_TYPE (dst->r_info);

	if (r_type >= (unsigned int) R_PU32_max) {
		// xgettext:c-format
		_bfd_error_handler (
			_("%pB: unsupported relocation type %#x"),
			abfd, r_type);

		bfd_set_error (bfd_error_bad_value);

		return false;
	}

	cache_ptr->howto = & pu32_elf_howto_table [r_type];

	return true;
}

static asection *pu32_elf_gc_mark_hook (
	asection *sec,
	struct bfd_link_info *info,
	Elf_Internal_Rela *rel,
	struct elf_link_hash_entry *h,
	Elf_Internal_Sym *sym) {

	return _bfd_elf_gc_mark_hook (sec, info, rel, h, sym);
}

#define SIZEOF_OPCODE sizeof(uint16_t)

#define sec_addr(sec) (((sec)->output_section ? (sec)->output_section->vma : 0) + (sec)->output_offset)

#define GOT_ENTRY_SIZE sizeof(uint32_t)
#define GOT_HEADER_SIZE (3*GOT_ENTRY_SIZE)

static bfd_reloc_status_type pu32_final_link_relocate (
	struct bfd_link_info *info,
	struct elf_link_hash_entry *h,
	asection *sec,
	reloc_howto_type *howto,
	bfd *input_bfd,
	asection *input_section,
	bfd_byte *contents,
	Elf_Internal_Rela *rel,
	bfd_vma relocation) {

	bfd_vma r_offset = rel->r_offset;

	contents += r_offset;

	struct elf_link_hash_table *htab = elf_hash_table(info);
	BFD_ASSERT (htab != NULL);

	if (h) {

		switch (h->root.type) {

			case bfd_link_hash_undefweak:

				// Replace instruction rli with li 0 such that
				// the address of the undefined weak symbol is 0.
				switch (howto->type) {

					case R_PU32_8:
					case R_PU32_8_PCREL: {
						uint16_t x = bfd_get_16 (input_bfd, contents);
						x = (x&0xf000)>>12; // Extract rli8 %gpr number.
						x = (0x80|(x<<12)); // Generate li8.
						bfd_put_16(input_bfd, (bfd_vma)x, contents);
						break;
					}

					case R_PU32_16:
					case R_PU32_16_PCREL: {
						contents -= SIZEOF_OPCODE;
						uint16_t x = bfd_get_16 (input_bfd, contents);
						x = (x&0xf000)>>12; // Extract rli16 %gpr1 number.
						x = (0xa9|(x<<12)); // Generate li16.
						bfd_put_16(input_bfd, (bfd_vma)x, contents);
						contents += SIZEOF_OPCODE;
						bfd_put_16(input_bfd, (bfd_vma)0, contents);
						break;
					}

					case R_PU32_32:
					case R_PU32_32_PCREL: {
						contents -= SIZEOF_OPCODE;
						uint16_t x = bfd_get_16 (input_bfd, contents);
						x = (x&0xf000)>>12; // Extract rli32 %gpr1 number.
						x = (0xaa|(x<<12)); // Generate li32.
						bfd_put_16(input_bfd, (bfd_vma)x, contents);
						contents += SIZEOF_OPCODE;
						bfd_put_16(input_bfd, (bfd_vma)0, contents);
						contents += sizeof(uint16_t);
						bfd_put_16(input_bfd, (bfd_vma)0, contents);
						break;
					}

					default:
						return bfd_reloc_notsupported;
				}

				return bfd_reloc_ok;

			default:

				if (!(
					h->got.offset >= GOT_HEADER_SIZE &&
					h->got.offset != (bfd_vma)-1))
					break;

				bfd_byte *opcode = (contents - SIZEOF_OPCODE);

				switch (*opcode) {
					case 0xae/* rli32 */:
						bfd_put_8 (input_bfd, 0xac/* drli */, opcode);
						break;
					default:
						return bfd_reloc_notsupported;
				}

				break;
		}
	}

	if (sec && sec->flags&SEC_THREAD_LOCAL) {
		asection *tlssec = htab->tls_sec;
		if (tlssec)
			relocation -= sec_addr(tlssec);
	}

	switch (howto->type) {

		case R_PU32_8:
		case R_PU32_8_PCREL: {
			// Sanity check the r_offset in section.
			if (r_offset > bfd_get_section_limit (input_bfd, input_section))
				return bfd_reloc_outofrange;

			relocation += rel->r_addend;

			if (howto->pc_relative) {

				relocation -= (
					input_section->output_section->vma +
					input_section->output_offset +
					(r_offset + SIZEOF_OPCODE));
			}

			if (((signed)relocation < -(1<<7)) || ((signed)relocation > ((1<<7)-1)))
				return bfd_reloc_overflow;

			uint16_t x = bfd_get_16 (input_bfd, contents);
			x = ((x&0xf0f0)|((relocation&0x0f)<<8)|((relocation>>4)&0x0f));
			bfd_put_16(input_bfd, (bfd_vma)x, contents);

			return bfd_reloc_ok;
		}

		case R_PU32_16:
		case R_PU32_16_PCREL: {
			// Sanity check the r_offset in section.
			if (r_offset > bfd_get_section_limit (input_bfd, input_section))
				return bfd_reloc_outofrange;

			relocation += rel->r_addend;

			if (howto->pc_relative) {

				relocation -= (
					input_section->output_section->vma +
					input_section->output_offset +
					(r_offset + sizeof(uint16_t)));
			}

			if (((signed)relocation < -(1<<15)) || ((signed)relocation > ((1<<15)-1)))
				return bfd_reloc_overflow;

			bfd_put_16(input_bfd, (bfd_vma)relocation, contents);

			return bfd_reloc_ok;
		}

		case R_PU32_32:
		case R_PU32_32_PCREL: {
			// Sanity check the r_offset in section.
			if (r_offset > bfd_get_section_limit (input_bfd, input_section))
				return bfd_reloc_outofrange;

			// Compute based on whether symbol has a GOT entry.
			if (h && h->got.offset >= GOT_HEADER_SIZE &&
				h->got.offset != (bfd_vma)-1)
				relocation = (sec_addr(htab->sgot) + h->got.offset);
			else
				relocation += rel->r_addend;

			if (howto->pc_relative) {

				relocation -= (
					input_section->output_section->vma +
					input_section->output_offset +
					(r_offset + sizeof(uint32_t)));
			}

			bfd_put_32(input_bfd, (bfd_vma)relocation, contents);

			return bfd_reloc_ok;
		}

		default:
			return bfd_reloc_notsupported;
	}
}

static int pu32_elf_relocate_section (
	bfd *output_bfd,
	struct bfd_link_info *info,
	bfd *input_bfd,
	asection *input_section,
	bfd_byte *contents,
	Elf_Internal_Rela *relocs,
	Elf_Internal_Sym *local_syms,
	asection **local_sections) {

	Elf_Internal_Shdr *symtab_hdr;
	struct elf_link_hash_entry **sym_hashes;
	Elf_Internal_Rela *rel;
	Elf_Internal_Rela *relend;

	symtab_hdr = &elf_tdata (input_bfd)->symtab_hdr;
	sym_hashes = elf_sym_hashes (input_bfd);
	relend     = relocs + input_section->reloc_count;

	for (rel = relocs; rel < relend; rel ++) {

		reloc_howto_type *howto;
		unsigned long r_symndx;
		Elf_Internal_Sym *sym;
		asection *sec;
		struct elf_link_hash_entry *h;
		bfd_vma relocation;
		bfd_reloc_status_type r;
		const char *name;
		int r_type;

		r_type = ELF32_R_TYPE (rel->r_info);
		r_symndx = ELF32_R_SYM (rel->r_info);
		howto  = pu32_elf_howto_table + r_type;
		h      = NULL;
		sym    = NULL;
		sec    = NULL;

		if (r_symndx < symtab_hdr->sh_info) {
			// We get here for a local symbol.

			sym = local_syms + r_symndx;
			sec = local_sections [r_symndx];
			relocation = _bfd_elf_rela_local_sym (output_bfd, sym, &sec, rel);

			name = bfd_elf_string_from_elf_section (input_bfd, symtab_hdr->sh_link, sym->st_name);
			name = (name ?: bfd_section_name (sec));

		} else {
			// We get here for a global symbol.

			struct elf_link_hash_table *htab = elf_hash_table(info);
			BFD_ASSERT (htab != NULL);
			if (htab->dynamic_sections_created) {
				info->unresolved_syms_in_objects = RM_IGNORE;
				info->unresolved_syms_in_shared_libs = RM_IGNORE;
			}

			bool unresolved_reloc, warned, ignored;

			RELOC_FOR_GLOBAL_SYMBOL (info, input_bfd, input_section, rel,
						r_symndx, symtab_hdr, sym_hashes,
						h, sec, relocation,
						unresolved_reloc, warned, ignored);

			name = h->root.root.string;
		}

		if (sec != NULL && discarded_section (sec))
			RELOC_AGAINST_DISCARDED_SECTION (
				info, input_bfd, input_section,
				rel, 1, relend, howto, 0, contents);

		if (bfd_link_relocatable (info))
			continue;

		r = pu32_final_link_relocate (
			info, h, sec, howto, input_bfd, input_section,
			contents, rel, relocation);

		if (r != bfd_reloc_ok) {

			const char *msg = NULL;

			switch (r) {

				case bfd_reloc_overflow:
					(*info->callbacks->reloc_overflow)
						(info, (h ? &h->root : NULL), name, howto->name,
						(bfd_vma) 0, input_bfd, input_section, rel->r_offset);
					break;

				case bfd_reloc_undefined:
					(*info->callbacks->undefined_symbol)
						(info, name, input_bfd, input_section, rel->r_offset, true);
					break;

				case bfd_reloc_outofrange:
					msg = _("internal error: out of range relocation");
					break;

				case bfd_reloc_notsupported:
					msg = _("internal error: unsupported relocation");
					break;

				case bfd_reloc_dangerous:
					msg = _("internal error: dangerous relocation");
					break;

				default:
					msg = _("internal error: unknown error");
					break;
			}

			if (msg)
				(*info->callbacks->warning) (
					info, msg, name, input_bfd,
					input_section, rel->r_offset);
		}
	}

	return true;
}

#define PRSTATUS_SIZE                   144
#define PRSTATUS_OFFSET_PR_CURSIG       12
#define PRSTATUS_OFFSET_PR_PID          24
#define PRSTATUS_OFFSET_PR_REG          72
#define ELF_GREGSET_T_SIZE              68

// Support for core dump NOTE sections.
static bool elf_pu32_grok_prstatus (bfd *abfd, Elf_Internal_Note *note) {
	switch (note->descsz) {
		default:
			return false;

		case PRSTATUS_SIZE: // sizeof(struct elf_prstatus) on Linux PU32.
			elf_tdata (abfd)->core->signal = bfd_get_16 (abfd, note->descdata + PRSTATUS_OFFSET_PR_CURSIG); // pr_cursig
			elf_tdata (abfd)->core->lwpid = bfd_get_32 (abfd, note->descdata + PRSTATUS_OFFSET_PR_PID); // pr_pid
			break;
	}

	// Make a ".reg/999" section.
	return _bfd_elfcore_make_pseudosection (abfd, ".reg", ELF_GREGSET_T_SIZE, note->descpos + PRSTATUS_OFFSET_PR_REG);
}

// Name of the dynamic interpreter; this is put in section .interp .
#define ELF_DYNAMIC_INTERPRETER "/lib/ld.so.1"

// Look through the relocs during the first phase,
// and allocate space in the global offset table.
static bool pu32_elf_check_relocs (
	bfd *abfd,
	struct bfd_link_info *info,
	asection *sec,
	const Elf_Internal_Rela *relocs) {

	if (bfd_link_relocatable(info))
		return true;

	struct elf_link_hash_table *htab = elf_hash_table(info);
	BFD_ASSERT (htab != NULL);

	if (!htab->dynamic_sections_created)
		return true;

	asection *sgot = htab->sgot;
	asection *srelgot = htab->srelgot;
	BFD_ASSERT (sgot != NULL && srelgot != NULL);

	Elf_Internal_Shdr *symtab_hdr = &elf_tdata(abfd)->symtab_hdr;
	struct elf_link_hash_entry **sym_hashes = elf_sym_hashes(abfd);

	const Elf_Internal_Rela *rel_end = relocs + sec->reloc_count;
	for (const Elf_Internal_Rela *rel = relocs; rel < rel_end; ++rel) {
		unsigned long r_symndx = ELF32_R_SYM(rel->r_info);
		if (r_symndx < symtab_hdr->sh_info) {
			/* We get here for a local symbol.
			They are resolved directly without
			creating a global offset table entry. */
			continue;
		} else {
			// We get here for a global symbol.
			struct elf_link_hash_entry *h =
				sym_hashes[r_symndx - symtab_hdr->sh_info];
			while (h->root.type == bfd_link_hash_indirect ||
				h->root.type == bfd_link_hash_warning)
				h = (struct elf_link_hash_entry *)h->root.u.i.link;
			if (h->got.offset >= GOT_HEADER_SIZE && h->got.offset != (bfd_vma)-1)
				continue;
			if (h->type == STT_TLS) {
				struct dtpmod_struct *dtpmod = bfd_malloc(sizeof(struct dtpmod_struct));
				dtpmod->next = h->dtpmod;
				// For a tls_object, the compiler generates the following
				// instruction sequence: li32 %1, 0; li %2, tls_symb; where
				// the first instruction load dtpmod aka tls_modid in %1.
				dtpmod->r_off = (rel->r_offset - (SIZEOF_OPCODE + sizeof(uint32_t)));
				h->dtpmod = dtpmod;
				// Allocate relocation space.
				srelgot->size += sizeof(Elf32_External_Rela);
			} else if (h->root.type == bfd_link_hash_undefined || h->def_dynamic) {
				// Allocate space in the .got section.
				h->got.offset = sgot->size;
				sgot->size += sizeof(uint32_t);
				// Allocate relocation space.
				srelgot->size += sizeof(Elf32_External_Rela);
			}
		}
	}

	return true;
}

// Adjust a symbol defined by a dynamic object
// and referenced by a regular object.
static bool pu32_elf_adjust_dynamic_symbol (
	struct bfd_link_info *info,
	struct elf_link_hash_entry *h) {

	struct elf_link_hash_table *htab = elf_hash_table(info);
	BFD_ASSERT (htab != NULL);
	bfd *dynobj = htab->dynobj;
	BFD_ASSERT (dynobj != NULL);

	BFD_ASSERT ((h->is_weakalias ||
		(h->def_dynamic && h->ref_regular && !h->def_regular)));

	/* If this is a weak symbol, and there is a real definition,
	the processor independent code will have arranged for us to see
	the real definition first, and we can just use the same value. */
	if (h->is_weakalias) {
		struct elf_link_hash_entry *def = weakdef(h);
		BFD_ASSERT (def->root.type == bfd_link_hash_defined);
		h->root.u.def.section = def->root.u.def.section;
		h->root.u.def.value = def->root.u.def.value;
		return true;
	}

	// This is a reference to a symbol defined
	// by a dynamic object which is not a function.

	/* If we are creating a shared library, we must presume that the
	only references to the symbol are via the global offset table.
	For such cases we need not do anything here; the relocations will
	be handled correctly by relocate_section.  */
	if (!bfd_link_executable(info))
		return true;

	// If there are no non-GOT references, we do not need a copy relocation.
	if (!h->non_got_ref)
		return true;

	// If -z nocopyreloc was given, we won't generate them either.
	if (info->nocopyreloc) {
		h->non_got_ref = 0;
		return true;
	}

	/* We must allocate the symbol in our .dynbss section,
	which will become part of the .bss section of the executable.
	There will be an entry for this symbol in the .dynsym section.
	The dynamic object will contain position independent code,
	so all references from the dynamic object to this symbol will go
	through the global offset table. The dynamic linker will use
	the .dynsym entry to determine the address it must put in
	the global offset table, so both the dynamic object and the regular
	object will refer to the same memory location for the variable. */

	asection *s;

	/* We must generate a copy-reloc to tell the dynamic linker
	to copy the initial value out of the dynamic object and into
	the runtime process image. We need to remember the offset
	into the .rela.bss section we are going to use.  */
	if ((h->root.u.def.section->flags & SEC_ALLOC) != 0 && h->size != 0) {
		s = htab->srelbss;
		BFD_ASSERT (s != NULL);
		s->size += sizeof(Elf32_External_Rela);
		h->needs_copy = 1;
	}

	s = htab->sdynbss;
	BFD_ASSERT (s != NULL);

	return _bfd_elf_adjust_dynamic_copy (info, h, s);
}

/* This function is called via elf_link_hash_traverse
to remove from the dynamic symbol table, references to symbols
that are not in the GOT and are not a defined object. */
static bool pu32_remove_from_dynamic_symbol_table (
		struct elf_link_hash_entry *h,
		void *data) {

	if ((h->root.type != bfd_link_hash_defined || h->type == STT_NOTYPE) && !(
		h->got.offset >= GOT_HEADER_SIZE &&
		h->got.offset != (bfd_vma)-1 &&
		h->dynindx != -1)) {

		struct bfd_link_info *info = (struct bfd_link_info *)data;
		h->dynindx = -1;
		_bfd_elf_strtab_delref (
			elf_hash_table(info)->dynstr,
			h->dynstr_index);
	}

	return true;
}

// Set the sizes of the dynamic sections.
static bool pu32_elf_size_dynamic_sections (
	bfd *output_bfd ATTRIBUTE_UNUSED,
	struct bfd_link_info *info) {

	struct elf_link_hash_table *htab = elf_hash_table(info);
	BFD_ASSERT (htab != NULL);
	bfd *dynobj = htab->dynobj;
	BFD_ASSERT (dynobj != NULL);

	if (htab->dynamic_sections_created) {
		// Set the contents of the .interp section to the interpreter.
		if (bfd_link_executable(info) && !info->nointerp) {
			asection *s = bfd_get_section_by_name (dynobj, ".interp");
			BFD_ASSERT (s != NULL);
			s->size = sizeof(ELF_DYNAMIC_INTERPRETER);
			s->contents = (unsigned char *)ELF_DYNAMIC_INTERPRETER;
		}
	}

	bool relocs_exist = false;
	bool reltext_exist = false;

	for (asection *s = dynobj->sections; s != NULL; s = s->next) {

		if ((s->flags & SEC_LINKER_CREATED) == 0)
			continue;

		if (	s == htab->splt ||
			s == htab->sgot ||
			s == htab->sgotplt ||
			s == htab->sdynbss ||
			s == htab->sdynrelro) {
			// Strip this section if we don't need it.
		} else if (strncmp (s->name, ".rela", 5) == 0) {
			if (s->size != 0 && s != htab->srelplt) {
				if (!reltext_exist) {
					const char *name = s->name + 5/* (sizeof(".rela")-1) */;
					for (bfd *ibfd = info->input_bfds; ibfd; ibfd = ibfd->link.next)
						if (bfd_get_flavour(ibfd) == bfd_target_elf_flavour &&
							(ibfd->flags & DYNAMIC)) {
							asection *target = bfd_get_section_by_name (ibfd, name);
							if (target != NULL &&
								elf_section_data(target)->sreloc == s &&
								((target->output_section->flags & (SEC_READONLY | SEC_ALLOC)) ==
									(SEC_READONLY | SEC_ALLOC))) {
								reltext_exist = true;
								break;
							}
						}
				}
				relocs_exist = true;
			}
			// We use the reloc_count field as a counter
			// if we need to copy relocs into the output file.
			s->reloc_count = 0;
		} else // It's not one of our sections, so don't allocate space.
			continue;

		if (s->size == 0) {
			s->flags |= SEC_EXCLUDE;
			continue;
		}

		if ((s->flags & SEC_HAS_CONTENTS) == 0)
			continue;

		// Allocate memory for the section contents.
		s->contents = bfd_zalloc (dynobj, s->size);
		BFD_ASSERT (s->contents != NULL);
	}

	if (htab->dynamic_sections_created) {
		if (bfd_link_executable(info))
			if (!_bfd_elf_add_dynamic_entry (info, DT_DEBUG, 0))
				return false;
		if (htab->sgot && (htab->sgot->flags & SEC_EXCLUDE) == 0)
			if (!_bfd_elf_add_dynamic_entry (info, DT_PLTGOT, 0))
				return false;
		if (relocs_exist)
			if (	!_bfd_elf_add_dynamic_entry (info, DT_RELA, 0) ||
				!_bfd_elf_add_dynamic_entry (info, DT_RELASZ, 0) ||
				!_bfd_elf_add_dynamic_entry (info, DT_RELAENT,
					sizeof(Elf32_External_Rela)))
				return false;
		if (reltext_exist)
			if (!_bfd_elf_add_dynamic_entry (info, DT_TEXTREL, 0))
				return false;
	}

	elf_link_hash_traverse (
		htab,
		pu32_remove_from_dynamic_symbol_table,
		info);

	return true;
}

// Finish up dynamic symbol handling.
// We set the contents of various dynamic sections here.
static bool pu32_elf_finish_dynamic_symbol (
	bfd *output_bfd,
	struct bfd_link_info *info,
	struct elf_link_hash_entry *h,
	Elf_Internal_Sym *sym ATTRIBUTE_UNUSED) {

	struct elf_link_hash_table *htab = elf_hash_table(info);
	BFD_ASSERT (htab != NULL);

	Elf_Internal_Rela rela;
	bfd_byte *loc;
	asection *srelgot;

	if (	h->got.offset >= GOT_HEADER_SIZE &&
		h->got.offset != (bfd_vma)-1 &&
		h->dynindx != -1) {
		// This symbol has an entry in the GOT; set it up.

		rela.r_info = ELF32_R_INFO (h->dynindx, R_PU32_32);
		rela.r_addend = 0;

		asection *sgot = htab->sgot;
		BFD_ASSERT (sgot != NULL);

		rela.r_offset = (sec_addr(sgot) + h->got.offset);

		// Fill-in the initial value of the .got entry.
		loc = (sgot->contents + h->got.offset);
		bfd_put_32 (output_bfd, 0, loc);

		srelgot = htab->srelgot;
		BFD_ASSERT (srelgot != NULL);

		// Fill-in the entry in the .rela section.
		loc = srelgot->contents + (srelgot->reloc_count++ * sizeof(Elf32_External_Rela));
		bfd_elf32_swap_reloca_out (output_bfd, &rela, loc);

	} else if (h->type == STT_TLS) {

		srelgot = htab->srelgot;
		BFD_ASSERT (srelgot != NULL);

		rela.r_info = ELF32_R_INFO (h->dynindx, R_PU32_32);
		rela.r_addend = 0;

		for (struct dtpmod_struct *dtpmod = h->dtpmod; dtpmod;) {

			rela.r_offset = dtpmod->r_off;

			struct dtpmod_struct *dtpmod_next = dtpmod->next;
			free(dtpmod);
			dtpmod = dtpmod_next;

			// Fill-in the entry in the .rela section.
			loc = srelgot->contents + (srelgot->reloc_count++ * sizeof(Elf32_External_Rela));
			bfd_elf32_swap_reloca_out (output_bfd, &rela, loc);
		}

		h->dtpmod = 0;
	}

	return true;
}

// Finish up the dynamic sections.
static bool pu32_elf_finish_dynamic_sections (
	bfd *output_bfd, struct bfd_link_info *info) {

	struct elf_link_hash_table *htab = elf_hash_table(info);
	BFD_ASSERT (htab != NULL);

	bfd *dynobj = htab->dynobj;
	BFD_ASSERT (dynobj != NULL);

	asection *sdyn = bfd_get_section_by_name (dynobj, ".dynamic");

	if (htab->dynamic_sections_created) {
		BFD_ASSERT (sdyn != NULL && htab->sgot != NULL);
		Elf32_External_Dyn *dyncon = (Elf32_External_Dyn *)sdyn->contents;
		Elf32_External_Dyn *dynconend = (Elf32_External_Dyn *)(sdyn->contents + sdyn->size);
		for (; dyncon < dynconend; ++dyncon) {
			Elf_Internal_Dyn dyn;
			bool issz = false;
			const char *name = NULL;
			bfd_elf32_swap_dyn_in (dynobj, dyncon, &dyn);
			switch (dyn.d_tag) {
				default:
					continue;
				case DT_RELA:
					name = ".rela.dyn";
					break;
				case DT_RELASZ:
					name = ".rela.dyn";
					issz = true;
					break;
				case DT_PLTGOT:
					dyn.d_un.d_ptr = (
						htab->sgot->output_section->vma +
						htab->sgot->output_offset);
					break;
			}
			if (name != NULL) {
				asection *s = bfd_get_section_by_name (output_bfd, name);
				if (s == NULL)
					dyn.d_un.d_val = 0;
				else if (issz)
					dyn.d_un.d_val = s->size;
				else
					dyn.d_un.d_ptr = s->vma;
			}
			bfd_elf32_swap_dyn_out (output_bfd, &dyn, dyncon);
		}
	}

	// Fill in the first three entries in the global offset table.
	asection *sgot = htab->sgot;
	if (sgot != NULL) {
		if (sgot->size > 0) {
			bfd_put_32 (
				output_bfd,
				(sdyn == NULL ?
					(bfd_vma)0 :
					(sdyn->output_section->vma + sdyn->output_offset)),
				sgot->contents);
			bfd_put_32 (
				output_bfd,
				(bfd_vma)0,
				(sgot->contents + sizeof(uint32_t)));
			bfd_put_32 (
				output_bfd,
				(bfd_vma)0,
				(sgot->contents + (2*sizeof(uint32_t))));
		}
		elf_section_data(sgot->output_section)->this_hdr.sh_entsize =
			sizeof(uint32_t);
	}

	return true;
}

// CPU-related basic API.
#define ELF_ARCH bfd_arch_pu32
#define ELF_MACHINE_CODE EM_PU32
#define ELF_MAXPAGESIZE 0x1000
#define TARGET_LITTLE_SYM pu32_elf32_vec
#define TARGET_LITTLE_NAME "elf32-pu32"

// GC section related API.
#define elf_backend_can_gc_sections 1
#define elf_backend_gc_mark_hook pu32_elf_gc_mark_hook

// Relocation related API.
#define elf_backend_rela_normal 1
#define elf_info_to_howto_rel NULL
#define elf_info_to_howto pu32_info_to_howto_rela
#define bfd_elf32_bfd_reloc_type_lookup pu32_reloc_type_lookup
#define bfd_elf32_bfd_reloc_name_lookup pu32_reloc_name_lookup
#define elf_backend_relocate_section pu32_elf_relocate_section

#define elf_backend_grok_prstatus elf_pu32_grok_prstatus

// Dynamic relocation related API.
#define elf_backend_plt_not_loaded 1
#define elf_backend_want_got_sym 1
#define elf_backend_want_dynbss 1
#define elf_backend_create_dynamic_sections _bfd_elf_create_dynamic_sections
#define elf_backend_check_relocs pu32_elf_check_relocs
#define elf_backend_adjust_dynamic_symbol pu32_elf_adjust_dynamic_symbol
#define elf_backend_size_dynamic_sections pu32_elf_size_dynamic_sections
#define elf_backend_finish_dynamic_symbol pu32_elf_finish_dynamic_symbol
#define elf_backend_finish_dynamic_sections pu32_elf_finish_dynamic_sections
#define elf_backend_got_header_size GOT_HEADER_SIZE

#include "elf32-target.h"
