#!/bin/sh

rm -rf ./debian; ln -sf debian_nonhdfs debian

# To be safe include -I flag
autoreconf --force --verbose --install
./configure --config-cache $*
