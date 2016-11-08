/* down & dirty ld script */
ENTRY(_start)

SECTIONS
{
	. = 0;

	.text :
	{
		*(.text)
		. = ALIGN(4);
	}

	.got :
	{
		*(.got)
		. = ALIGN(4);
	}

	.got.plt :
	{
		*(.got.plt)
		. = ALIGN(4);
	}

	.rodata :
	{
		*(.rodata)
		. = ALIGN(4);
	}

	.data :
	{
		*(.data)
		. = ALIGN(4);
	}

	.bss :
	{
		*(COMMON)
		*(.bss)
		. = ALIGN(4);
	}

	/DISCARD/ : {
		*(.eh_frame);
		*(.comment);
		*(.note.gnu.build-id);
	}
}

