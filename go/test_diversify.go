package main

import (
    "fmt"
    "encoding/hex"
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
    appkey_str := "00112233445566778899AABBCCDDEEFF"
    appkey, err := hex.DecodeString(appkey_str)
    if err != nil {
        panic(err)
    }
    fmt.Println(appkey)

    aid_str := "3042F5"
    aid, err := hex.DecodeString(aid_str)
    if err != nil {
        panic(err)
    }
    fmt.Println(aid)

    sysid_str := "4E585020416275"
    sysid, err := hex.DecodeString(sysid_str)
    if err != nil {
        panic(err)
    }
    fmt.Println(sysid)


    uidstr := "04782E21801D80"
    uidbytes, err := hex.DecodeString(uidstr);
    if err != nil {
        panic(err);
    }
    fmt.Println(uidstr)
    fmt.Println(uidbytes)

    uidaid := make([]byte, len(uidbytes)+len(aid)+len(sysid)+1)
    uidaid[0] =0x01
    copy(uidaid[1:], uidbytes)
    copy(uidaid[len(uidbytes)+1:], aid)
    copy(uidaid[len(uidbytes)+len(aid)+1:], sysid)

//    D, padded := padUID(uidaid)
//    fmt.Println("D=", hex.EncodeToString(D), "padded=", padded)
    
    foo, err := cmac.New(appkey)
    if err != nil {
        panic(err)
    }
//    fmt.Println(foo, err)
    n, err := foo.Write(uidaid)
    fmt.Println(n)
    bar := foo.Sum(uidaid)
    
//    fmt.Println(hex.EncodeToString(bar))
    
    dkey := bar[len(uidaid):]

    fmt.Println(hex.EncodeToString(dkey))
    

}    

