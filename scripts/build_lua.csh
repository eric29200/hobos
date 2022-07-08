#!/bin/csh

# setup environement
setenv MUSL_CC		`pwd`"/musl/musl-1.2.3-build/bin/musl-gcc"

# create port directory if needed
mkdir ports >& /dev/null
cd ports

# create directory if needed
mkdir lua >& /dev/null
cd lua

# cleanup directories
rm -rf *

# download lua sources
wget https://www.lua.org/ftp/lua-5.4.4.tar.gz
tar -xzvf lua-5.4.4.tar.gz

# build lua
cd lua-5.4.4
make -j8 CC=$MUSL_CC LDFLAGS="-static"
