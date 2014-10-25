package main

import (
    "github.com/fuzxxl/nfc/2.0/nfc"    
    "github.com/fuzxxl/freefare/0.3/freefare"    
    "fmt"
)

func main() {
    fmt.Println("Hello, 世界");
    d, err := nfc.Open("");
    fmt.Println(err);
    fmt.Println(d.Information());
    tags, err := freefare.GetTags(d);
    fmt.Println(err);
    fmt.Println(tags);
    for i := 0; i < len(tags); i++ {
        tag := tags[i]
        fmt.Println(tag.UID())
    }
}
