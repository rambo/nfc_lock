package main

import (
    "github.com/fuzxxl/nfc/2.0/nfc"    
    "github.com/fuzxxl/freefare/0.3/freefare"    
    "fmt"
    "encoding/hex"
)

func main() {
    d, err := nfc.Open("");
    fmt.Println(err);
    fmt.Println(d.Information());
    tags, err := freefare.GetTags(d);
    if err != nil {
        panic(err);
    }
    fmt.Println(tags);
    for i := 0; i < len(tags); i++ {
        tag := tags[i]
        uidstr := tag.UID()
        uidbytes, err := hex.DecodeString(uidstr);
        if err != nil {
            panic(err);
        }
        fmt.Println(uidstr)
        fmt.Println(uidbytes)
    }
}
