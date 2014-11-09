package main

import (
    "fmt"
    "encoding/hex"
    "encoding/binary"
    "github.com/fuzxxl/nfc/2.0/nfc"    
    "github.com/fuzxxl/freefare/0.3/freefare"
    "./keydiversification"
    "./helpers"
)

// TODO: move to a separate helper module


func main() {
    keymap, err := helpers.LoadYAMLFile("keys.yaml")
    if err != nil {
        panic(err)
    }

    appmap, err := helpers.LoadYAMLFile("apps.yaml")
    if err != nil {
        panic(err)
    }

    // Application-id from config
    aidbytes, err := hex.DecodeString(appmap["hacklab_acl"].(map[interface{}]interface{})["aid"].(string))
    if err != nil {
        panic(err)
    }
    aidint, n := binary.Uvarint(aidbytes)
    if n <= 0 {
        panic(fmt.Sprintf("binary.Uvarint returned %d", n))
    }
    aid := freefare.NewDESFireAid(uint32(aidint))
    //fmt.Println(aid)
    // Needed for diversification
    sysid, err := hex.DecodeString(appmap["hacklab_acl"].(map[interface{}]interface{})["sysid"].(string))
    if err != nil {
        panic(err)
    }

    // Key id numbers from config
    uid_read_key_id, err := helpers.String2byte(appmap["hacklab_acl"].(map[interface{}]interface{})["uid_read_key_id"].(string))
    if err != nil {
        panic(err)
    }
    acl_read_key_id, err := helpers.String2byte(appmap["hacklab_acl"].(map[interface{}]interface{})["acl_read_key_id"].(string))
    if err != nil {
        panic(err)
    }
    acl_file_id, err := helpers.String2byte(appmap["hacklab_acl"].(map[interface{}]interface{})["acl_file_id"].(string))
    if err != nil {
        panic(err)
    }
    mid_file_id, err := helpers.String2byte(appmap["hacklab_acl"].(map[interface{}]interface{})["mid_file_id"].(string))
    if err != nil {
        panic(err)
    }

    // The static app key to read UID
    uid_read_key, err := helpers.String2aeskey(keymap["uid_read_key"].(string))
    if err != nil {
        panic(err)
    }
    //fmt.Println(uid_read_key)

    // Bases for the diversified keys    
    acl_read_base, err := hex.DecodeString(keymap["acl_read_key"].(string))
    if err != nil {
        panic(err)
    }

    // Open device and get tags list
    d, err := nfc.Open("");
    if err != nil {
        panic(err)
    }

    tags, err := freefare.GetTags(d);
    if err != nil {
        panic(err)
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
        error = desfiretag.SelectApplication(aid);
        if error != nil {
            panic(error)
        }
        fmt.Println("Done");

        fmt.Println("Authenticating");
        error = desfiretag.Authenticate(uid_read_key_id,*uid_read_key)
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

        // Calculate the diversified keys
        acl_read_bytes, err := keydiversification.AES128(acl_read_base, aidbytes, realuid, sysid)
        if err != nil {
            panic(err)
        }
        acl_read_key := helpers.Bytes2aeskey(acl_read_bytes)

        fmt.Println("Re-auth with ACL read key")
        error = desfiretag.Authenticate(acl_read_key_id,*acl_read_key)
        if error != nil {
            panic(error)
        }

        aclbytes := make([]byte, 8)
        fmt.Println("Reading ACL data file")
        bytesread, err := desfiretag.ReadData(acl_file_id, 0, aclbytes)
        if error != nil {
            panic(error)
        }
        if (bytesread < 8) {
            panic(fmt.Sprintf("ReadData read %d bytes, 8 expected", bytesread))
        }
        acl, n := binary.Uvarint(aclbytes)
        if n <= 0 {
            panic(fmt.Sprintf("binary.Uvarint returned %d", n))
        }
        fmt.Println("acl:", acl)

        midbytes := make([]byte, 2)
        fmt.Println("Reading member-id data file")
        bytesread, err = desfiretag.ReadData(mid_file_id, 0, midbytes)
        if error != nil {
            panic(error)
        }
        // TODO: make a helper that repeatedly reads until we're past the buffer or readbytes == 0
        if (bytesread < 2) {
            //panic(fmt.Sprintf("ReadData read %d bytes, 2 expected", bytesread))
            fmt.Println(fmt.Sprintf("ReadData read %d bytes, 2 expected", bytesread))
        }
        mid, n := binary.Uvarint(midbytes)
        if n <= 0 {
            panic(fmt.Sprintf("binary.Uvarint returned %d", n))
        }
        fmt.Println("mid:", mid)



        fmt.Println("Disconnecting");
        error = desfiretag.Disconnect()
        if error != nil {
            panic(error)
        }
        fmt.Println("Done");
    }

}