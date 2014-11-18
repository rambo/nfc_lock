package keydiversification

import(
    "testing"
    "bytes"
    "fmt"
    "encoding/hex"
);

func TestAES128(t *testing.T) {
    appkey_str := "00112233445566778899AABBCCDDEEFF"
    appkey, err := hex.DecodeString(appkey_str)
    if err != nil {
        panic(err)
    }
    //fmt.Println(appkey)

    aid_str := "3042F5"
    aid, err := hex.DecodeString(aid_str)
    if err != nil {
        panic(err)
    }
    //fmt.Println(aid)

    sysid_str := "4E585020416275"
    sysid, err := hex.DecodeString(sysid_str)
    if err != nil {
        panic(err)
    }
    //fmt.Println(sysid)


    uid_str := "04782E21801D80"
    uid, err := hex.DecodeString(uid_str);
    if err != nil {
        panic(err);
    }
    //fmt.Println(uid)


    expect_newkey_str := "A8DD63A3B89D54B37CA802473FDA9175"
    expect_newkey, err := hex.DecodeString(expect_newkey_str);
    if err != nil {
        panic(err);
    }
    //fmt.Println(expect_newkey)


    newkey, err := AES128(appkey[:], aid[:], uid[:], sysid[:]);
    
    if (!bytes.Equal(newkey, expect_newkey)) {
        t.Errorf("Returned key %s does not match expected %s", hex.EncodeToString(newkey), hex.EncodeToString(expect_newkey));
    }

    fmt.Sprintf("Got key %s\n", hex.EncodeToString(newkey));
}