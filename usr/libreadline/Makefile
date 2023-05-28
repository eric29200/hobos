CC		= i686-linux-gnu-gcc
AR		= i686-linux-gnu-ar
LIBC		= ../libc/libc.a
CFLAGS		= -O0 -Wall -Wextra -nostdinc -fno-builtin -fno-stack-protector -fno-pic -I../../libc/include -ffreestanding -nostdlib -m32

LIBREADLINE 	= libreadline.a
LIBREADLINE_SRC	= $(wildcard *.c)
LIBREADLINE_OBJ	= $(LIBREADLINE_SRC:.c=.o)

all: $(LIBREADLINE)

$(LIBREADLINE): $(LIBREADLINE_OBJ)
	$(AR) rc $@ $?

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(LIBREADLINE) $(LIBREADLINE_OBJ)
