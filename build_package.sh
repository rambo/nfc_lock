#!/bin/bash
set -x
if [ -e build ]
then
    rm -rf build
fi
set -e
mkdir -p build/etc/init
mkdir -p build/opt/nfc_lock/bin
cd c
make gatekeeper
cd ..
cp -aux c/gatekeeper build/opt/nfc_lock/bin/
cp -aux python/keyserver.py build/opt/nfc_lock/bin/
cp -aux python/card_watcher.py build/opt/nfc_lock/bin/
cp -aux python/usergpio.py build/opt/nfc_lock/bin/
cp -aux python/requirements.txt build/opt/nfc_lock/python_requirements.txt
cp -aux bash/sync_keydb.sh build/opt/nfc_lock/bin/
cp -aux upstart/*.conf build/etc/init/
cd build
tar -cvzf ../nfc_lock-`uname -m`-`date +%Y%m%d_%H%M`.tar.gz ./
cd ..
rm -rf build
