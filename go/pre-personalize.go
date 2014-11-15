package main

import (
    "fmt"
    "encoding/hex"
    "github.com/fuzxxl/nfc/2.0/nfc"    
    "github.com/fuzxxl/freefare/0.3/freefare"
    "./keydiversification"
    "./helpers"
)


func main() {
    keymap, err := helpers.LoadYAMLFile("keys.yaml")
    if err != nil {
        panic(err)
    }

    appmap, err := helpers.LoadYAMLFile("apps.yaml")
    if err != nil {
        panic(err)
    }

    // Application-id
    aid, err := helpers.String2aid(appmap["hacklab_acl"].(map[interface{}]interface{})["aid"].(string))
    if err != nil {
        panic(err)
    }

    // Needed for diversification
    aidbytes := helpers.Aid2bytes(aid)
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
    acl_write_key_id, err := helpers.String2byte(appmap["hacklab_acl"].(map[interface{}]interface{})["acl_write_key_id"].(string))
    if err != nil {
        panic(err)
    }
    prov_key_id, err := helpers.String2byte(appmap["hacklab_acl"].(map[interface{}]interface{})["provisioning_key_id"].(string))
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

    // Defaul (null) key
    nullkeydata := new([8]byte)
    defaultkey := freefare.NewDESFireDESKey(*nullkeydata)

    nullkeydata16 := new([16]byte)
    defaultkey_aes := freefare.NewDESFireAESKey(*nullkeydata16, 0)


    // New card master key
    new_master_key, err := helpers.String2aeskey(keymap["card_master"].(string))
    if err != nil {
        panic(err)
    }
    //fmt.Println(new_master_key)

    // The static app key to read UID
    uid_read_key, err := helpers.String2aeskey(keymap["uid_read_key"].(string))
    if err != nil {
        panic(err)
    }
    //fmt.Println(uid_read_key)

    // Bases for the diversified keys    
    prov_key_base, err := hex.DecodeString(keymap["prov_master"].(string))
    if err != nil {
        panic(err)
    }
    acl_read_base, err := hex.DecodeString(keymap["acl_read_key"].(string))
    if err != nil {
        panic(err)
    }
    acl_write_base, err := hex.DecodeString(keymap["acl_write_key"].(string))
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

        fmt.Println("Authenticating");
        error = desfiretag.Authenticate(0,*defaultkey)
        if error != nil {
            fmt.Println("Failed, trying agin with new key")
            error = desfiretag.Authenticate(0,*new_master_key)
            if error != nil {
                panic(error)
            }
            fmt.Println("Changing key back to default")
            error = desfiretag.ChangeKey(0,  *defaultkey, *new_master_key);
            if error != nil {
                panic(error)
            }
            fmt.Println("Re-auth with default key")
            error = desfiretag.Authenticate(0,*defaultkey)
            if error != nil {
                panic(error)
            }
            fmt.Println("Disabling random id")
            error = desfiretag.SetConfiguration(false, false)
            if error != nil {
                panic(error)
            }
            fmt.Println("Formatting (to get a clean state)")
            error = desfiretag.FormatPICC()
            if error != nil {
                panic(error)
            }
            return
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
        //fmt.Println("realuid:", hex.EncodeToString(realuid));

        // Calculate the diversified keys
        prov_key_bytes, err := keydiversification.AES128(prov_key_base, aidbytes, realuid, sysid)
        if err != nil {
            panic(err)
        }
        prov_key := helpers.Bytes2aeskey(prov_key_bytes)
        acl_read_bytes, err := keydiversification.AES128(acl_read_base, aidbytes, realuid, sysid)
        if err != nil {
            panic(err)
        }
        acl_read_key := helpers.Bytes2aeskey(acl_read_bytes)
        acl_write_bytes, err := keydiversification.AES128(acl_write_base, aidbytes, realuid, sysid)
        if err != nil {
            panic(err)
        }
        acl_write_key := helpers.Bytes2aeskey(acl_write_bytes)


        // Start working...
        fmt.Println("Changing default master key");
        error = desfiretag.ChangeKey(0, *new_master_key, *defaultkey);
        if error != nil {
            panic(error)
        }
        fmt.Println("Done");

        fmt.Println("Creating application");
        // Settings are: only master key may change other keys, configuration is not locked, authentication required for everything, AMK change allowed
        error = desfiretag.CreateApplication(aid, helpers.Applicationsettings(0x0, false, true, true, true), freefare.CryptoAES | 6);
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

        fmt.Println("Re-auth with null AES key")
        error = desfiretag.Authenticate(prov_key_id,*defaultkey_aes)
        if error != nil {
            panic(error)
        }

        fmt.Println("Changing provisioning key");
        error = desfiretag.ChangeKey(prov_key_id, *prov_key, *defaultkey_aes);
        if error != nil {
            panic(error)
        }
        fmt.Println("Done");

        fmt.Println("Re-auth with provisioning key")
        error = desfiretag.Authenticate(prov_key_id,*prov_key)
        if error != nil {
            panic(error)
        }


        fmt.Println("Changing ACL reading key");
        error = desfiretag.ChangeKey(acl_read_key_id, *acl_read_key, *defaultkey_aes);
        if error != nil {
            panic(error)
        }
        fmt.Println("Done");


        fmt.Println("Changing ACL writing key");
        error = desfiretag.ChangeKey(acl_write_key_id, *acl_write_key, *defaultkey_aes);
        if error != nil {
            panic(error)
        }
        fmt.Println("Done");

        fmt.Println("Changing static UID reading key");
        error = desfiretag.ChangeKey(uid_read_key_id, *uid_read_key, *defaultkey_aes);
        if error != nil {
            panic(error)
        }
        fmt.Println("Done");



        fmt.Println("Creating ACL data file");
        error = desfiretag.CreateDataFile(acl_file_id, freefare.Enciphered, freefare.MakeDESFireAccessRights(acl_read_key_id, acl_write_key_id, prov_key_id, prov_key_id), 4, true)
        if error != nil {
            panic(error)
        }
        fmt.Println("Done");

        fmt.Println("Creating member-id data file");
        error = desfiretag.CreateDataFile(mid_file_id, freefare.Enciphered, freefare.MakeDESFireAccessRights(acl_read_key_id, prov_key_id, prov_key_id, prov_key_id), 2, true)
        if error != nil {
            panic(error)
        }
        fmt.Println("Done");

        /**
         * Only needed when working with backup files
        // Not sure if this is actually needed
        fmt.Println("Committing");
        error = desfiretag.CommitTransaction()
        if error != nil {
            panic(error)
        }
        fmt.Println("Done");
         */


        /**
         * Enable this only when 100% everything else works perfectly    
        fmt.Println("Enabling random ID");
        error = desfiretag.SetConfiguration(false, true)
        if error != nil {
            panic(error)
        }
        fmt.Println("Done");
         */


        fmt.Println("Disconnecting");
        error = desfiretag.Disconnect()
        if error != nil {
            panic(error)
        }
        fmt.Println("Done");
    }

}