package main

import (
    "github.com/fuzxxl/nfc/1.0/nfc"    
//    "github.com/fuzxxl/freefare/0.3/freefare"    
    "fmt"
)

func main() {
    fmt.Println("Hello, 世界");
    d, err := nfc.Open("");
    fmt.Println(err);
    fmt.Println(d.Information());
    
}
