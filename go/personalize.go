package main

import (
    "gopkg.in/yaml.v2"
    "io/ioutil"
    "fmt"
    "encoding/hex"
    "github.com/fuzxxl/nfc/2.0/nfc"    
    "github.com/fuzxxl/freefare/0.3/freefare"
//    "./keydiversification"
)

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

    nullkeydata := new([8]byte)
    defaultkey := freefare.NewDESFireDESKey(*nullkeydata)
    
    newkeydata := new([16]byte)
    newkeydata_str := keymap["card_master"].(string)
    to_newkeydata, err := hex.DecodeString(newkeydata_str)
    if err != nil {
        panic(err)
    }
    copy(newkeydata[0:], to_newkeydata)
    fmt.Println(newkeydata)
    newkey := freefare.NewDESFireAESKey(*newkeydata, 0)
    fmt.Println(newkey)

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
    		error = desfiretag.Authenticate(0,*newkey)
    		if error != nil {
                panic(error)
            }
		}
        fmt.Println("Done");


        fmt.Println("Changing key");
        error = desfiretag.ChangeKey(0, *newkey, *defaultkey);
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