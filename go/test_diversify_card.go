package main

import (
    "fmt"
    "encoding/hex"
    //"runtime"
    "time"
    "encoding/binary"
    "github.com/fuzxxl/nfc/2.0/nfc"    
    "github.com/fuzxxl/freefare/0.3/freefare"
    "./keydiversification"
    "./helpers"
)

// Use structs to pass data around so I can refactor 
type AppInfo struct {
    aid freefare.DESFireAid
    aidbytes []byte
    sysid []byte
    acl_read_base []byte
    acl_write_base []byte
    acl_file_id byte
    mid_file_id byte
}

type KeyChain struct {
    uid_read_key_id byte
    acl_read_key_id byte
    acl_write_key_id byte

    uid_read_key *freefare.DESFireKey
    acl_read_key *freefare.DESFireKey
    acl_write_key *freefare.DESFireKey
}

var (
    keychain = KeyChain{}
    appinfo = AppInfo{}
)

func init_appinfo() {
    keymap, err := helpers.LoadYAMLFile("keys.yaml")
    if err != nil {
        panic(err)
    }

    appmap, err := helpers.LoadYAMLFile("apps.yaml")
    if err != nil {
        panic(err)
    }

    // Application-id
    appinfo.aid, err = helpers.String2aid(appmap["hacklab_acl"].(map[interface{}]interface{})["aid"].(string))
    if err != nil {
        panic(err)
    }

    // Needed for diversification
    appinfo.aidbytes = helpers.Aid2bytes(appinfo.aid)
    appinfo.sysid, err = hex.DecodeString(appmap["hacklab_acl"].(map[interface{}]interface{})["sysid"].(string))
    if err != nil {
        panic(err)
    }

    appinfo.acl_file_id, err = helpers.String2byte(appmap["hacklab_acl"].(map[interface{}]interface{})["acl_file_id"].(string))
    if err != nil {
        panic(err)
    }
    appinfo.mid_file_id, err = helpers.String2byte(appmap["hacklab_acl"].(map[interface{}]interface{})["mid_file_id"].(string))
    if err != nil {
        panic(err)
    }


    // Key id numbers from config
    keychain.uid_read_key_id, err = helpers.String2byte(appmap["hacklab_acl"].(map[interface{}]interface{})["uid_read_key_id"].(string))
    if err != nil {
        panic(err)
    }
    keychain.acl_read_key_id, err = helpers.String2byte(appmap["hacklab_acl"].(map[interface{}]interface{})["acl_read_key_id"].(string))
    if err != nil {
        panic(err)
    }
    keychain.acl_write_key_id, err = helpers.String2byte(appmap["hacklab_acl"].(map[interface{}]interface{})["acl_write_key_id"].(string))
    if err != nil {
        panic(err)
    }

    // The static app key to read UID
    keychain.uid_read_key, err = helpers.String2aeskey(keymap["uid_read_key"].(string))
    if err != nil {
        panic(err)
    }

    // Bases for the diversified keys    
    appinfo.acl_read_base, err = hex.DecodeString(keymap["acl_read_key"].(string))
    if err != nil {
        panic(err)
    }
    appinfo.acl_write_base, err = hex.DecodeString(keymap["acl_write_key"].(string))
    if err != nil {
        panic(err)
    }

}

func recalculate_diversified_keys(realuid []byte) error {
    acl_read_bytes, err := keydiversification.AES128(appinfo.acl_read_base[:], appinfo.aidbytes[:], realuid[:], appinfo.sysid[:])
    if err != nil {
        return err
    }
    acl_write_bytes, err := keydiversification.AES128(appinfo.acl_write_base[:], appinfo.aidbytes[:], realuid[:], appinfo.sysid[:])
    if err != nil {
        return err
    }
    keychain.acl_read_key = helpers.Bytes2aeskey(acl_read_bytes)
    keychain.acl_write_key = helpers.Bytes2aeskey(acl_write_bytes)
    return nil
}

func handle_tag(desfiretag *freefare.DESFireTag) {
    desfiretag.Connect()

    uid_str := desfiretag.UID()
    
    fmt.Printf("Found tag %s\n", uid_str)

    fmt.Println("Selecting application");
    err := desfiretag.SelectApplication(appinfo.aid);
    if err != nil {
        panic(err)
    }
    fmt.Println("Done");

    fmt.Println("Authenticating");
    err = desfiretag.Authenticate(keychain.uid_read_key_id,*keychain.uid_read_key)
    if err != nil {
        panic(err)
    }
    fmt.Println("Done");

    realuid_str, err := desfiretag.CardUID()
    if err != nil {
        panic(err)
    }

    realuid, err := hex.DecodeString(realuid_str)
    if err != nil {
        fmt.Println(fmt.Sprintf("ERROR: Failed to parse real UID (%s), skipping tag", err))
        return
    }
    fmt.Println("Got UID: ", hex.EncodeToString(realuid));

    // Calculate the diversified keys
    err = recalculate_diversified_keys(realuid)
    if err != nil {
        fmt.Println(fmt.Sprintf("ERROR: Failed to get diversified ACL keys (%s), skipping tag", err))
        return
    }

    fmt.Println("Got real ACL read key: ", keychain.acl_read_key)

    fmt.Print("Re-auth with ACL read key, ")
    err = desfiretag.Authenticate(keychain.acl_read_key_id,*keychain.acl_read_key)
    if err != nil {
        fmt.Println(fmt.Sprintf("ERROR: Failed (%s), skipping tag", err))
        return
    }
    fmt.Println("Done")

    /*
    aclbytes := make([]byte, 8)
    fmt.Print("Reading ACL data file, ")
    bytesread, err := desfiretag.ReadData(appinfo.acl_file_id, 0, aclbytes)
    if err != nil {
        fmt.Println(fmt.Sprintf("ERROR: Failed (%s), skipping tag", err))
        return
    }
    if (bytesread < 8) {
        fmt.Println(fmt.Sprintf("WARNING: ReadData read %d bytes, 8 expected", bytesread))
    }
    acl, n := binary.Uvarint(aclbytes)
    if n <= 0 {
        fmt.Println(fmt.Sprintf("ERROR: binary.Uvarint returned %d, skipping tag", n))
        return
    }
    fmt.Println("Done")
    fmt.Println("acl:", acl)
    */

    midbytes := make([]byte, 2)
    fmt.Println("Reading member-id data file")
    bytesread, err := desfiretag.ReadData(appinfo.mid_file_id, 0, midbytes)
    if err != nil {
        fmt.Println(fmt.Sprintf("ERROR: Failed (%s), skipping tag", err))
        return
    }
    if (bytesread < 2) {
        //panic(fmt.Sprintf("ReadData read %d bytes, 2 expected", bytesread))
        fmt.Println(fmt.Sprintf("ReadData read %d bytes, 2 expected", bytesread))
    }
    mid64, n := binary.Uvarint(midbytes)
    if n <= 0 {
        fmt.Println(fmt.Sprintf("ERROR: binary.Uvarint returned %d, skipping tag", n))
        return
    }
    mid := uint16(mid64)
    fmt.Println("Done")
    fmt.Println("mid:", mid)



    desfiretag.Disconnect()
}

func main() {

    init_appinfo();

    d, err := nfc.Open("");
    if err != nil {
        panic(err)
    }

    for {
        var tags []freefare.Tag
        for {
            tags, err = freefare.GetTags(d);
            if err != nil {
                continue
            }
            if len(tags) > 0 {
                break
            }
            time.Sleep(100 * time.Millisecond)
            //fmt.Println("...polling")
        }
    
        for i := 0; i < len(tags); i++ {
            tag := tags[i]
            desfiretag := tag.(freefare.DESFireTag)
            handle_tag(&desfiretag)
        }
        //runtime.GC()
    }

}    

