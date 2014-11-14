package main

import (
    "fmt"
    "errors"
    "time"
    "runtime"
    "encoding/hex"
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

func read_and_parse_mid_file(desfiretag *freefare.DESFireTag) (uint16, error) {
    // already authenticated
    midbytes := make([]byte, 2)
    fmt.Println("Reading member-id data file")
    bytesread, err := desfiretag.ReadData(appinfo.mid_file_id, 0, midbytes)
    if err != nil {
        return 0,err
    }
    if (bytesread < 2) {
        //panic(fmt.Sprintf("ReadData read %d bytes, 2 expected", bytesread))
        fmt.Println(fmt.Sprintf("ReadData read %d bytes, 2 expected", bytesread))
    }
    mid64, n := binary.Uvarint(midbytes)
    if n <= 0 {
        return 0, errors.New(fmt.Sprintf("ERROR: binary.Uvarint returned %d, skipping tag", n))        
    }
    mid := uint16(mid64)
    fmt.Println("Done")
    return mid, nil
}

func read_and_parse_acl_file(desfiretag *freefare.DESFireTag) (uint64, error) {
    fmt.Print("Re-auth with ACL read key, ")
    err := desfiretag.Authenticate(keychain.acl_read_key_id,*keychain.acl_read_key)
    if err != nil {
        return 0, err
    }
    fmt.Println("Done")

    aclbytes := make([]byte, 8)
    fmt.Print("Reading ACL data file, ")
    bytesread, err := desfiretag.ReadData(appinfo.acl_file_id, 0, aclbytes)
    if err != nil {
        return 0, err
    }
    if (bytesread < 8) {
        fmt.Println(fmt.Sprintf("WARNING: ReadData read %d bytes, 8 expected", bytesread))
    }
    acl, n := binary.Uvarint(aclbytes)
    if n <= 0 {
        return 0, errors.New(fmt.Sprintf("ERROR: binary.Uvarint returned %d, skipping tag", n))
    }
    fmt.Println("Done")
    return acl, nil
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
            runtime.GC()
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
    
        // Initialize each tag with our app
        for i := 0; i < len(tags); i++ {
            tag := tags[i]
            fmt.Println(tag.String(), tag.UID())
    
            // Skip non desfire tags
            if (tag.Type() != freefare.DESFire) {
                fmt.Println("Skipped");
                continue
            }
            
            desfiretag := tag.(freefare.DESFireTag)
    
            // Connect to this tag
            fmt.Println("Connecting");
            error := desfiretag.Connect()
            if error != nil {
                panic(error)
            }
            fmt.Println("Done");
    
            fmt.Println("Selecting application");
            error = desfiretag.SelectApplication(appinfo.aid);
            if error != nil {
                panic(error)
            }
            fmt.Println("Done");
    
            fmt.Println("Authenticating");
            error = desfiretag.Authenticate(keychain.uid_read_key_id,*keychain.uid_read_key)
            if error != nil {
                panic(error)
            }
            fmt.Println("Done");
    
            // Get card real UID        
            realuid_str, error := desfiretag.CardUID()
            if error != nil {
                panic(error)
            }
            realuid, error := hex.DecodeString(realuid_str);
            if error != nil {
                panic(error)
            }
            fmt.Println("realuid:", hex.EncodeToString(realuid));

            realuid, err := hex.DecodeString(realuid_str)
            if err != nil {
                fmt.Println(fmt.Sprintf("ERROR: Failed to parse real UID (%s), skipping tag", err))
                continue
            }
            fmt.Println("Got UID: ", hex.EncodeToString(realuid));
        
            // Calculate the diversified keys
            err = recalculate_diversified_keys(realuid[:])
            if err != nil {
                fmt.Println(fmt.Sprintf("ERROR: Failed to get diversified ACL keys (%s), skipping tag", err))
                continue
            }

            fmt.Println("Got real ACL read key: ", keychain.acl_read_key)

            acl, err := read_and_parse_acl_file(&desfiretag)
            if err != nil {
                fmt.Println(fmt.Sprintf("ERROR: Failed to read ACL (%s), skipping tag", err))
                continue
            }
            fmt.Println("acl:", acl)
            
            mid, err := read_and_parse_mid_file(&desfiretag)
            if err != nil {
                fmt.Println(fmt.Sprintf("ERROR: Failed to read MID (%s), skipping tag", err))
                continue
            }

            fmt.Println("mid:", mid)
    
            fmt.Println("Disconnecting");
            error = desfiretag.Disconnect()
            if error != nil {
                continue
            }
            fmt.Println("Done");


        }
    }

}    



