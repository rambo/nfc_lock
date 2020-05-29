#!/bin/bash

TARGET=/opt/nfc_lock
NFCUSER=hacklab

echo "Stop services.."
service gatekeeper stop
service keyserver stop
service card_watcher stop

echo "Install files.."
install -dm 700 -o $NFCUSER $TARGET/bin
install -m 700 -o $NFCUSER python/keyserver.py $TARGET/bin
install -m 600 -o $NFCUSER python/usergpio.py $TARGET/bin
install -m 700 -o $NFCUSER python/card_watcher.py $TARGET/bin
install -m 700 -o $NFCUSER c/gatekeeper $TARGET/bin
install -m 600 -o $NFCUSER python/config.yml $TARGET/
install -m 700 -o $NFCUSER bash/sync_keydb.sh $TARGET/bin

echo "Install systemd scripts.."
SYSD=/etc/systemd/system/
cp systemd/* $SYSD
systemctl daemon-reload

echo "Start services.."
service gatekeeper start
systemctl enable gatekeeper

service card_watcher start
systemctl enable card_watcher

service keyserver start
systemctl enable keyserver


