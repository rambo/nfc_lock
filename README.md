nfc_lock
========

(more) secure electric lock with DESFire EV1 NFC tags

## libnfc and libfreefare

Ubuntu 14.04 has libnfc but no libfreefare, use [this PPA](https://launchpad.net/~christopher-hoskin/+archive/ubuntu/ppa)

    sudo apt-add-repository ppa:christopher-hoskin/ppa
    sudo apt-get update
    sudo apt-get install libnfc5 libnfc-bin libnfc-pn53x-examples libnfc-examples
    sudo apt-get install libfreefare0 libfreefare-bin
    sudo apt-get install python-zmq python-yaml python-tornado

`python-yaml` and `python-tornado` can be installed to virtualenv (esp tornado might be better to install via pip even if not to virtualenv the deb pulls unneccessary dependencies), zmq will be painful to install via pip, use the system package.

### For compiling

For the C programs.

    sudo apt-get install libfreefare-dev libnfc-dev libssl-dev pkg-config libzmq-dev

### RasPi

Install the debs from [./raspi/debs/](./raspi/debs/) (or compile them using source debs from Jessie)

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

### RasPi

It seems Valgrind does not (and will not) support some instructions we use to talk with the NFC chips, see (this stackoverflow)[valgrindworkaround] for a workaround.

[valgrindworkaround]: http://stackoverflow.com/questions/20066215/valgrind-unrecognizes-memcmp-instruction-in-raspberry-pi#comment-29892760
