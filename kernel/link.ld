ENTRY(loader)

SECTIONS {
	kernel_start = 0x100000;
	. = 0x00100000;

	.text ALIGN (0x1000) :
	{
		*(.multiboot)
		*(.text)
	}

	.rodata ALIGN (0x1000) :
	{
		*(.rodata)
	}

	.data ALIGN (0x1000) :
	{
		*(.data)
	}

	.bss ALIGN (0x1000) :
	{
		*(COMMON)
		*(.bss)
	}

	kernel_end = .;
}
