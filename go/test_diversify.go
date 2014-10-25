package main

import (
    "gopkg.in/yaml.v2"
    "io/ioutil"
    "fmt"
    "encoding/hex"
    "github.com/fuzxxl/nfc/2.0/nfc"    
    "github.com/fuzxxl/freefare/0.3/freefare"    
)

func padUID(block []byte) ([]byte, bool) {
	blockLen := len(block)
	if blockLen >= 32 {
		panic("PadBlock input must be less than 32 bytes.")
	}
	if blockLen == 32 {
	   return block, false
	}

	result := make([]byte, 32)
	copy(result, block)
	result[blockLen] = 0x80

	return result, true
}

func main() {
    dat, err := ioutil.ReadFile("keys.yaml")
    if err != nil {
        panic(err)
    }

    m := make(map[interface{}]interface{});
    err = yaml.Unmarshal([]byte(dat), &m);
    if err != nil {
        panic(err)
    }

    appkey_str := m["aclapp"].(map[interface{}]interface{})["read"].(string)
    appkey, err := hex.DecodeString(appkey_str)
    if err != nil {
        panic(err)
    }
    fmt.Println(appkey)

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
        
        
        fmt.Println("Found tag", uidstr)

        D, padded := padUID(uidbytes)
        fmt.Println("D=", D, " padded=", padded)
    }

}    

