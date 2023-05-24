KERNEL		= kernel/kernel.bin
ISO		= hobos.iso
NJOBS		= $(shell nproc)
MEM_SIZE	= 512M
DISK		= hda.img
QEMU		= kvm
args		= `arg="$(filter-out $@,$(MAKECMDGOALS))" && echo $${arg:-${1}}`

all: run

run:
	make -j$(NJOBS) -C kernel
	make -j$(NJOBS) -C libc
	make -j$(NJOBS) -C usr
	cp $(KERNEL) iso/boot/
	grub-mkrescue -o $(ISO) iso
	./scripts/create_rootfs.sh
	sudo $(QEMU)								\
		-m $(MEM_SIZE)							\
		-serial stdio 							\
		-boot order=d 							\
		-cdrom $(ISO) 							\
		-drive format=raw,file=$(DISK)					\
		-netdev tap,id=hobos_net					\
		-device rtl8139,netdev=hobos_net,id=hobos_nic			\
		-object filter-dump,id=f1,netdev=hobos_net,file=./traffic.pcap

%:
	@:

clean:
	make clean -C kernel
	make clean -C libc
	make clean -C usr
	rm -f $(ISO)
