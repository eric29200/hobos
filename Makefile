AS		= nasm
CC		= i386-elf-gcc
LD		= i386-elf-ld
C_SOURCES 	= $(wildcard *.c */*.c)
OBJ 		= ${C_SOURCES:.c=.o}
CFLAGS		= -nostdlib -nostdinc -fno-builtin -fno-stack-protector
LDFLAGS		= -Tboot/link.ld
ASFLAGS		= -felf
QEMU		= qemu-system-i386

all: run

%.o: %.c
	${CC} ${CFLAGS} -c $< -o $@

%.o: %.s
	$(AS) $(ASFLAGS) $<

kernel.bin: boot/boot.o $(OBJ)
	$(LD) $(LDFLAGS) -o $@ $^

run: kernel.bin
	sudo losetup /dev/loop0 grub/floppy.img
	sudo mount /dev/loop0 grub/mnt
	sudo cp kernel.bin grub/mnt/kernel
	sudo umount grub/mnt
	sudo losetup -d /dev/loop0
	$(QEMU) -fda grub/floppy.img

clean:
	rm -f *.o */*.o kernel.bin
