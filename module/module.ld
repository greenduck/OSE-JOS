/* Simple linker script for the JOS kernel.
   See the GNU ld 'info' manual ("info ld") to learn the syntax. */

OUTPUT_FORMAT("elf32-i386")
OUTPUT_ARCH(i386)

SECTIONS
{
	.rodata :
	{
		*(.rodata .rodata.* .gnu.linkonce.r.*)
	}

	/DISCARD/ :
	{
		*(.eh_frame .note.GNU-stack)
		*(.discard)
	}
}

