package main

import (
    "gopkg.in/yaml.v2"
    "io/ioutil"
    "fmt"
    "encoding/hex"
    "encoding/binary"
    "github.com/fuzxxl/nfc/2.0/nfc"    
    "github.com/fuzxxl/freefare/0.3/freefare"
//    "./keydiversification"
)

// TODO: move to a separate helper module
func string_to_aeskey(keydata_str string) (NewDESFireAESKey, error) {
    keydata := new([16]byte)
    to_keydata, err := hex.DecodeString(keydata_str)
    if err != nil {
        return nil,err
    }
    copy(keydata[0:], to_keydata)
    fmt.Println(new_master_keydata)
    key := freefare.NewDESFireAESKey(*keydata, 0)
    return key,nil
}

func main() {
    keys_data, err := ioutil.ReadFile("keys.yaml")
    if err != nil {
        panic(err)
    }

    keymap := make(map[interface{}]interface{});
    err = yaml.Unmarshal([]byte(keys_data), &keymap);
    if err != nil {
        panic(err)
    }

    apps_data, err := ioutil.ReadFile("apps.yaml")
    if err != nil {
        panic(err)
    }

    appmap := make(map[interface{}]interface{});
    err = yaml.Unmarshal([]byte(apps_data), &appmap);
    if err != nil {
        panic(err)
    }

    aidbytes, err := hex.DecodeString(appmap["hacklab_acl"].(map[interface{}]interface{})["aid"].(string))
    if err != nil {
        panic(err)
    }
    aidint, n := binary.Uvarint(aidbytes)
    if n <= 0 {
        panic(fmt.Sprintf("binary.Uvarint returned %d", n))
    }
    aid := freefare.NewDESFireAid(uint32(aidint))
    fmt.Println(aid)

    nullkeydata := new([8]byte)
    defaultkey := freefare.NewDESFireDESKey(*nullkeydata)

    new_master_key, err := string_to_aeskey(keymap["card_master"].(string))
    if err != nil {
        panic(err)
    }
    fmt.Println(new_master_key)

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
		}
        fmt.Println("Done");


        fmt.Println("Changing default key");
        error = desfiretag.ChangeKey(0, *new_master_key, *defaultkey);
		if error != nil {
			panic(error)
		}
        fmt.Println("Done");


        fmt.Println("Creating application");
        // TODO:Figure out what the settings byte (now hardcoded to 0xFF as it was in libfreefare exampkle code) actually does
        error = desfiretag.CreateApplication(aid, 0xFF, 6 | freefare.CryptoAES);
		if error != nil {
			panic(error)
		}
        fmt.Println("Done");


        fmt.Println("Selecting application");
        // TODO:Figure out what the settings byte (now hardcoded to 0xFF as it was in libfreefare exampkle code) actually does
        error = desfiretag.SelectApplication(aid);
		if error != nil {
			panic(error)
		}
        fmt.Println("Done");

        fmt.Println("Changing static auth key");
        error = desfiretag.ChangeKey(0, *new_master_key, *defaultkey);
		if error != nil {
			panic(error)
		}
        fmt.Println("Done");



        fmt.Println("Disconnecting");
		error = desfiretag.Disconnect()
		if error != nil {
			panic(error)
		}
        fmt.Println("Done");
    }

}