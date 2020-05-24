#!/bin/bash

TARGET=/opt/nfc_lock

echo "Stop services.."
service gatekeeper stop
service keyserver stop
service card_watcher stop

echo "Install files.."
mkdir -p $TARGET/bin
cp python/keyserver.py $TARGET/bin
cp python/usergpio.py $TARGET/bin
cp python/card_watcher.py $TARGET/bin
cp c/gatekeeper $TARGET/bin
cp python/config.yml $TARGET/

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


