#!/bin/csh

# setup environement
#setenv TARGET		i386
setenv SYSROOT		`pwd`/sysroot
setenv CC		$SYSROOT"/bin/musl-gcc"
setenv LD		$SYSROOT"/bin/musl-gcc"
setenv INSTALL_DIR	`pwd`/root/
setenv CFLAGS		"-static"
setenv LDFLAGS		"-static"
setenv NJOBS		8

# create port directory if needed
mkdir ports >& /dev/null
cd ports

# create directory if needed
mkdir busybox >& /dev/null
cd busybox

# cleanup directories
rm -rf *

# download busybox sources
wget https://busybox.net/downloads/busybox-1.35.0.tar.bz2
tar -xjvf busybox-1.35.0.tar.bz2

# build busybox
cd busybox-1.35.0
cp ../../../config/busybox.config .config
make -j$NJOBS CC=$CC
make install CC=$CC
