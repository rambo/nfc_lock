package main

import (
    "gopkg.in/yaml.v2"
    "io/ioutil"
    "fmt"
    "encoding/hex"
    "github.com/fuzxxl/nfc/2.0/nfc"    
    "github.com/fuzxxl/freefare/0.3/freefare"
    "github.com/jacobsa/crypto/cmac"
)

func padUID(block []byte) ([]byte, bool) {
	blockLen := len(block)
	if blockLen >= 32 {
		panic("PadBlock input must be less than 32 bytes.")
	}

	result := make([]byte, 32)
	copy(result, block)
	result[blockLen] = 0x80

	if blockLen == 31 {
	   return result, false
	}

	return result, true
}

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
        uidstr := tag.UID()
        uidbytes, err := hex.DecodeString(uidstr);
        if err != nil {
            panic(err);
        }
        fmt.Println(uidstr)
        fmt.Println(uidbytes)

    	uidaid := make([]byte, len(uidbytes)+len(aid)+1)
    	uidaid[0] =0x01
    	copy(uidaid[1:], uidbytes)
    	copy(uidaid[len(uidbytes)+1:], aid)

        fmt.Printf("Found tag %s\n", uidstr)

        D, padded := padUID(uidaid)
        fmt.Println("D=", D, "padded=", padded)
        
        foo, err := cmac.New(D)
        fmt.Println(foo)
// dafuq, how are we supposed to access those subkeys
//        fmt.Println(foo.k1)
//        fmt.Println(foo.k2)
    }

}    

