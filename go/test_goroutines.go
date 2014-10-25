package main

import (
    "fmt"
    "github.com/fuzxxl/nfc/2.0/nfc"    
    "github.com/fuzxxl/freefare/0.3/freefare"    
//    "code.google.com/p/go-sqlite/go1/sqlite3"
    "time"
)

func heartbeat() {
    for {
        time.Sleep(2000 * time.Millisecond)
        fmt.Println("Dunka-dunk")
    }
}

func main() {
    d, err := nfc.Open("");
    if err != nil {
        panic(err);
    }

    go heartbeat()
    // mainlopp
    for {
        // Poll for tags
        var tags []freefare.Tag
        for {
            tags, err = freefare.GetTags(d);
            if err != nil {
                panic(err);
            }
            if len(tags) > 0 {
                break;
            }
            time.Sleep(100 * time.Millisecond)
            //fmt.Println("...polling")
        }
        for i := 0; i < len(tags); i++ {
            tag := tags[i]
            uidstr := tag.UID()
            fmt.Println("Found tag", uidstr);
            // TODO: Check tag
        }
    }
}
