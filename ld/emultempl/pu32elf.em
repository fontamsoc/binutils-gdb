# SPDX-License-Identifier: GPL-2.0-only
# (c) William Fonkou Tambe

fragment <<EOF

static void
pu32_elf_after_open (void)
{
  gld${EMULATION_NAME}_after_open ();
}

static void
pu32_elf_before_allocation (void)
{
  gld${EMULATION_NAME}_before_allocation ();
}

static void
pu32_elf_after_allocation (void)
{
  gld${EMULATION_NAME}_after_allocation ();
}
EOF

LDEMUL_AFTER_OPEN=pu32_elf_after_open
LDEMUL_BEFORE_ALLOCATION=pu32_elf_before_allocation
LDEMUL_AFTER_ALLOCATION=pu32_elf_after_allocation
