KERNEL		= kernel/kernel.bin
ISO		= nulix.iso
NJOBS		= 8
MEM_SIZE	= 512M
DISK1		= hda.img
DISK2		= hdb.img
QEMU		= qemu-system-i386
args		= `arg="$(filter-out $@,$(MAKECMDGOALS))" && echo $${arg:-${1}}`

all: run

run:
	make -j$(NJOBS) -C kernel
	make -j$(NJOBS) -C usr
	cp $(KERNEL) iso/boot/
	grub-mkrescue -o $(ISO) iso
	./scripts/create_rootfs.csh
	sudo $(QEMU)								\
		-m $(MEM_SIZE)							\
		-serial stdio 							\
		-cdrom $(ISO) 							\
		-drive format=raw,file=$(DISK1)					\
		-drive format=raw,file=$(DISK2)					\
		-netdev tap,id=nulix_net					\
		-device rtl8139,netdev=nulix_net,id=nulix_nic			\
		-object filter-dump,id=f1,netdev=nulix_net,file=./traffic.pcap

musl:
	./ports/install_musl.csh
	./ports/install_linux-headers.csh
	./ports/install_pkgconf.csh

%:
	@:

port:
	./ports/install.csh $(call args)

clean:
	make clean -C kernel
	make clean -C usr
	rm -f $(DISK) $(ISO)
