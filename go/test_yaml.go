package main

import (
    "gopkg.in/yaml.v2"
    "io/ioutil"
    "fmt"
    "encoding/hex"
)

func main() {
    dat, err := ioutil.ReadFile("keys.yaml");
    if err != nil {
        panic(err);
    }
//    fmt.Println(dat);
    
    m := make(map[interface{}]interface{});
    err = yaml.Unmarshal([]byte(dat), &m);
    fmt.Println(m);
    
    foo := m["aclapp"]
    fmt.Println(foo);
    // ugh....
    key := foo.(map[interface{}]interface{})["read"].(string)
    fmt.Println(key);

    keybytes, err := hex.DecodeString(key);
    fmt.Println(keybytes);
}