CC		= i686-linux-gnu-gcc
AR		= i686-linux-gnu-ar
LIBC		= ../../libc/libc.a
CFLAGS		= -O0 -Wall -Wextra -nostdinc -fno-builtin -fno-stack-protector -fno-pic -I../../libc/include -ffreestanding -nostdlib -m32
BUILD_DIR	= ../build/sbin
LIBUTILS 	= ../libutils/libutils.a
LIBREADLINE	= ../libreadline/libreadline.a
LDFLAGS		= $(LIBUTILS) $(LIBREADLINE) $(LIBC) -lgcc -static

PROGS		= init login

all: $(PROGS)

$(PROGS): %: %.c
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $(BUILD_DIR)/$@ $< $(LDFLAGS)

clean:
	rm -f $(BUILD_DIR)/*
