CC		= i686-linux-gnu-gcc
AR		= i686-linux-gnu-ar
LIBC		= ../../libc/libc.a
LIBUTILS	= ../libutils/libutils.a
LIBREADLINE	= ../libreadline/libreadline.a
CFLAGS		= -O0 -Wall -Wextra -nostdinc -fno-builtin -fno-stack-protector -fno-pic -I../../libc/include -ffreestanding -nostdlib -m32
LDFLAGS		= $(LIBUTILS) $(LIBREADLINE) $(LIBC) -lgcc -static
BUILD_DIR	= ../build/bin

all: sh

sh: sh.o cmd.o alias.o job.o redir.o utils.o
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $(BUILD_DIR)/$@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $<

clean:
	rm -f *.o $(BUILD_DIR)/sh
