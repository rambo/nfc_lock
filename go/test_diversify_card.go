package main

import (
    "gopkg.in/yaml.v2"
    "io/ioutil"
    "fmt"
    "encoding/hex"
    "github.com/fuzxxl/nfc/2.0/nfc"    
    "github.com/fuzxxl/freefare/0.3/freefare"
    "./keydiversification"
)

func main() {
    dat, err := ioutil.ReadFile("keys.yaml")
    if err != nil {
        panic(err)
    }

    keymap := make(map[interface{}]interface{});
    err = yaml.Unmarshal([]byte(dat), &keymap);
    if err != nil {
        panic(err)
    }

    dat2, err := ioutil.ReadFile("apps.yaml")
    if err != nil {
        panic(err)
    }

    appmap := make(map[interface{}]interface{});
    err = yaml.Unmarshal([]byte(dat2), &appmap);
    if err != nil {
        panic(err)
    }

    appkey_str := keymap["aclapp"].(map[interface{}]interface{})["read"].(string)
    appkey, err := hex.DecodeString(appkey_str)
    if err != nil {
        panic(err)
    }
    fmt.Println(appkey)

    aid_str := appmap["aclapp"].(map[interface{}]interface{})["aid"].(string)
    aid, err := hex.DecodeString(aid_str)
    if err != nil {
        panic(err)
    }
    fmt.Println(aid)

    sysid := make([]byte, 0);


    d, err := nfc.Open("");
    if err != nil {
        panic(err)
    }

    tags, err := freefare.GetTags(d);
    if err != nil {
        panic(err)
    }

    for i := 0; i < len(tags); i++ {
        tag := tags[i]
        uid_str := tag.UID()
        uid, err := hex.DecodeString(uid_str);
        if err != nil {
            panic(err);
        }
        fmt.Println(uid_str)
        fmt.Println(uid)

        fmt.Printf("Found tag %s\n", uid_str)

        dkey, err := keydiversification.AES128(appkey, aid, uid, sysid);
        if err != nil {
            panic(err);
        }
        
        fmt.Println(hex.EncodeToString(dkey))
    }

}    

