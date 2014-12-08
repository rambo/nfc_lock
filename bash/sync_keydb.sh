#!/bin/bash
scp "$1":keys.db keys.db.new
diff -q keys.db keys.db.new
DIFFRET=$?
if [ "$DIFFRET" -eq "2" ]
then
# trouble
  exit 1
fi
if [ "$DIFFRET" -eq "0" ]
then
  rm keys.db.new
  exit 0
fi
mv -f keys.db.new keys.db
sudo restart keyserver
