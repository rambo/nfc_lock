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

    key := m["card_master"].(string)
    fmt.Println(key);
    keybytes, err := hex.DecodeString(key);
    fmt.Println(keybytes);

    dat2, err := ioutil.ReadFile("apps.yaml");
    if err != nil {
        panic(err);
    }
    m2 := make(map[interface{}]interface{});
    err = yaml.Unmarshal([]byte(dat2), &m2);
    fmt.Println(m2);
    
    
//    foo := m["aclapp"]
//    fmt.Println(foo);
    // ugh....
    aid := m2["hacklab_acl"].(map[interface{}]interface{})["aid"].(string)
    fmt.Println(aid);
    aidbytes, err := hex.DecodeString(aid);
    fmt.Println(aidbytes);

}