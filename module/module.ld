/* Simple linker script for the JOS kernel.
   See the GNU ld 'info' manual ("info ld") to learn the syntax. */

OUTPUT_FORMAT("elf32-i386")
OUTPUT_ARCH(i386)
/* ENTRY(_start) */

SECTIONS
{
	.text :
	{
		*(.text .stub .text.* .gnu.linkonce.t.*)
	}

/*	PROVIDE(etext = .);	*/

	.rodata :
	{
		*(.rodata .rodata.* .gnu.linkonce.r.*)
	}

	/* debugging information */
	.stab : {
		PROVIDE(__STAB_BEGIN__ = .);
		*(.stab);
		PROVIDE(__STAB_END__ = .);
		BYTE(0)
	}

	.stabstr : {
		PROVIDE(__STABSTR_BEGIN__ = .);
		*(.stabstr);
		PROVIDE(__STABSTR_END__ = .);
		BYTE(0)
	}

/*	. = ALIGN(0x1000); */

	.data :
	{
		*(.data)
	}

/*	PROVIDE(edata = .); */

	.bss :
	{
		*(.bss)
	}

/*	PROVIDE(end = .); */

	/DISCARD/ :
	{
		*(.eh_frame .note.GNU-stack)
	}
}

