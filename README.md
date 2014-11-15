nfc_lock
========

(more) secure electric lock with DESFire EV1 NFC tags

## libnfc and libfreefare

Ubuntu 14.04 has libnfc but no libfreefare, use [this PPA](https://launchpad.net/~christopher-hoskin/+archive/ubuntu/ppa)

    sudo apt-add-repository ppa:christopher-hoskin/ppa
    sudo apt-get update
    sudo apt-get install libnfc5 libnfc-bin libnfc-pn53x-examples libnfc-examples
    sudo apt-get install libfreefare0 libfreefare-bin

### For compiling

For the C programs and possibly the Go libraries.

    sudo apt-get install libfreefare-dev libnfc-dev libssl-dev pkg-config

### RasPi

Install the debs from [./raspi/debs/](./raspi/debs/) (or compile them using source debs from Jessie)

## Go

Install Go and some deps you are going to need when fetching Go libraries

    sudo apt-get install golang mercurial git-core

Make sure your GOPATH is set

    mkdir $HOME/.go
    export GOPATH=$HOME/.go
    export PATH=$PATH:$GOPATH/bin

Install library dependencies

    go get github.com/fuzxxl/nfc/2.0/nfc
    go get github.com/fuzxxl/freefare/0.3/freefare
    go get gopkg.in/yaml.v2
    go get github.com/jacobsa/crypto/cmac
    go get github.com/mattn/go-sqlite3
    go get github.com/davecheney/gpio

### RasPi

See https://xivilization.net/~marek/blog/2014/07/05/go-1-dot-3-for-raspberry-pi/ for Go 1.3 (1.0 will not work)

    sudo apt-get install apt-transport-https

Then edit `/etc/apt/sources.list.d/xivilization-raspbian.list` and switch to https

## Terms

  - Card (PICC in NXP terms): The DESFire EV1 chip+antenna in a package (fob, card, sticker...)
  - Pre-Personalization step: Where card default master key is changed and applications are defined.
  - Application: collection of files on the card, application can have multiple keys for various purposes
  - Provisioning (or personalization) step: Where a personalized card is issued to a card holder and the card (plus backing datababase) is updated with relevant info
  - Diversified key: Key that has been derived from a master key via the method described in NXP AN19022

## SQLite for keys

Create a test file `sqlite3 keys.db`:

    CREATE TABLE keys(uid TEXT UNIQUE, acl INTEGER);
    CREATE TABLE revoked(uid TEXT UNIQUE);

Prepare some tags and insert their (real) UIDs to the grants and revokes

    INSERT INTO revoked VALUES ("04453069b21e80");
    INSERT INTO keys VALUES ("04212f69b21e80", 1);

In reality you will generate this file based on your person registry (keep track of validity times etc there, then regenerate the keydb for the door).

## Hacking

Remember to valgrind your C programs (`valgrind -v --leak-check=yes  myprog args`) at the same time as you do general functionality testing.
