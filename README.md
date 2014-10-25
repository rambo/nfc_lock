nfc_lock
========

(more) secure electric lock with DESFire EV1 NFC tags


## Go

Install Go and some deps you are going to need when fetching Go libraries

    apt-get install golang mercurial git-core

Make sure your GOPATH is set

    mkdir $HOME/go
    export GOPATH=$HOME/go
    export PATH=$PATH:$GOPATH/bin

Install library dependencies

    go get github.com/fuzxxl/nfc/2.0/nfc
    go get github.com/fuzxxl/freefare/0.3/freefare
    go get gopkg.in/yaml.v2
    go get github.com/jacobsa/crypto/cmac
    go get code.google.com/p/go-sqlite/go1/sqlite3

### RasPi

See https://xivilization.net/~marek/blog/2014/06/10/go-1-dot-2-for-raspberry-pi/ for Go 1.2 (1.0 will not work)

    sudo apt-get install apt-transport-https

Then edit `/etc/apt/sources.list.d/xivilization-raspbian.list` and switch to https

