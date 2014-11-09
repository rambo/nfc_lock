package main

import (
    "fmt"
	"os"
	"os/signal"
    "encoding/hex"
    "github.com/fuzxxl/nfc/2.0/nfc"    
    "github.com/fuzxxl/freefare/0.3/freefare"    
    "code.google.com/p/go-sqlite/go1/sqlite3"
    "time"
    "github.com/davecheney/gpio"
    "./keydiversification"
    "./helpers"
)

func heartbeat() {
    for {
        time.Sleep(2000 * time.Millisecond)
        fmt.Println("Dunka-dunk")
    }
}

func pulse_gpio(pin gpio.Pin, ms int) {
    pin.Set()
    time.Sleep(time.Duration(ms) * time.Millisecond)
    pin.Clear()
}

func clear_and_close(pin gpio.Pin) {
    pin.Clear()
    pin.Close()
}



func main() {
    keymap, err := helpers.LoadYAMLFile("keys.yaml")
    if err != nil {
        panic(err)
    }

    appmap, err := helpers.LoadYAMLFile("apps.yaml")
    if err != nil {
        panic(err)
    }

    gpiomap, err := helpers.LoadYAMLFile("gpio.yaml")
    if err != nil {
        panic(err)
    }

    // Get cursor
    c, err := sqlite3.Open("keys.db")
    if err != nil {
        panic(err);
    }
    row := make(sqlite3.RowMap)

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
    acl_file_id, err := helpers.String2byte(appmap["hacklab_acl"].(map[interface{}]interface{})["acl_file_id"].(string))
    if err != nil {
        panic(err)
    }

    // The static app key to read UID
    uid_read_key, err := helpers.String2aeskey(keymap["uid_read_key"].(string))
    if err != nil {
        panic(err)
    }

    // Bases for the diversified keys    
    acl_read_base, err := hex.DecodeString(keymap["acl_read_key"].(string))
    if err != nil {
        panic(err)
    }


    // Open NFC device
    d, err := nfc.Open("");
    if err != nil {
        panic(err);
    }

    // Start heartbeat goroutine
    go heartbeat()

    // Get open GPIO pins for our outputs
	green_led, err := gpio.OpenPin(gpiomap["green_led"].(map[interface{}]interface{})["pin"].(int), gpio.ModeOutput)
	if err != nil {
		fmt.Printf("Error opening green_led! %s\n", err)
		return
	}
	red_led, err := gpio.OpenPin(gpiomap["red_led"].(map[interface{}]interface{})["pin"].(int), gpio.ModeOutput)
	if err != nil {
		fmt.Printf("Error opening green_led! %s\n", err)
		return
	}
	relay, err := gpio.OpenPin(gpiomap["relay"].(map[interface{}]interface{})["pin"].(int), gpio.ModeOutput)
	if err != nil {
		fmt.Printf("Error opening relay! %s\n", err)
		return
	}
	// turn the leds off on exit
	exit_ch := make(chan os.Signal, 1)
	signal.Notify(exit_ch, os.Interrupt)
	signal.Notify(exit_ch, os.Kill)
	go func() {
		for _ = range exit_ch {
			fmt.Printf("\nClearing and unexporting the pins.\n")
			go clear_and_close(green_led)
			go clear_and_close(red_led)
			go clear_and_close(relay)
			os.Exit(0)
		}
	}()

    // mainloop
    for {
        // Poll for tags
        var tags []freefare.Tag
        for {
            tags, err = freefare.GetTags(d);
            if err != nil {
                panic(err);
            }
            if len(tags) > 0 {
                break;
            }
            time.Sleep(100 * time.Millisecond)
            //fmt.Println("...polling")
        }
        valid_found := false
        i := 0
        errcnt := 0
        /**
         * I'm doing this in a funky way since I may need to restart discussion with a tag due to RF-errors
         for i := 0; i < len(tags); i++ {
         */
        for {
            if i >= len(tags) {
                break
            }
            tag := tags[i]

            // Skip non desfire tags
            if (tag.Type() != freefare.DESFire) {
                fmt.Println(fmt.Sprintf("Non-DESFire tag %s skipped", tag.UID()))
                i++
                errcnt = 0
                continue
            }

            desfiretag := tag.(freefare.DESFireTag)

            // Connect to this tag
            fmt.Print(fmt.Sprintf("Connecting to %s, ", tag.UID()))
            error := desfiretag.Connect()
            if error != nil {
                fmt.Println("failed, skipping tag");
                i++
                continue
            }
            fmt.Println("done")

            fmt.Print(fmt.Sprintf("Selecting application %d, ", aid.Aid()))
            error = desfiretag.SelectApplication(aid);
            if error != nil {
                // TODO: Retry only on RF-errors
                errcnt++
                if errcnt < 3 {
                    fmt.Println(fmt.Sprintf("failed (%s), retrying", error))
                    continue
                }
                fmt.Println(fmt.Sprintf("failed (%s), retry-count exceeded, skipping tag", error))
                i++
                errcnt = 0
                continue
            }
            fmt.Println("Done")

            fmt.Print("Authenticating, ")
            error = desfiretag.Authenticate(uid_read_key_id,*uid_read_key)
            if error != nil {
                // TODO: Retry only on RF-errors
                errcnt++
                if errcnt < 3 {
                    fmt.Println(fmt.Sprintf("failed (%s), retrying", error))
                    continue
                }
                fmt.Println(fmt.Sprintf("failed (%s), retry-count exceeded, skipping tag", error))
                i++
                errcnt = 0
                continue
            }
            fmt.Println("Done")

            // Get card real UID        
            realuid_str, error := desfiretag.CardUID()
            if error != nil {
                // TODO: Retry only on RF-errors
                errcnt++
                if errcnt < 3 {
                    fmt.Println(fmt.Sprintf("Failed to read card real UID (%s), retrying", error))
                    continue
                }
                fmt.Println(fmt.Sprintf("Failed to read card real UID (%s), retry-count exceeded, skipping tag", error))
                i++
                errcnt = 0
                continue
            }
            realuid, error := hex.DecodeString(realuid_str)
            if error != nil {
                fmt.Println(fmt.Sprintf("Failed to parse real UID (%s), skipping tag", error))
                i++
                errcnt = 0
                continue
            }
            fmt.Println("Got real UID:", hex.EncodeToString(realuid));

            // Calculate the diversified keys
            acl_read_bytes, err := keydiversification.AES128(acl_read_base, aidbytes, realuid, sysid)
            if err != nil {
                panic(err)
            }
            acl_read_key := helpers.Bytes2aeskey(acl_read_bytes)
    
            fmt.Print("Re-auth with ACL read key, ")
            error = desfiretag.Authenticate(acl_read_key_id,*acl_read_key)
            if error != nil {
                // TODO: Retry only on RF-errors
                errcnt++
                if errcnt < 3 {
                    fmt.Println(fmt.Sprintf("failed (%s), retrying", error))
                    continue
                }
                fmt.Println(fmt.Sprintf("failed (%s), retry-count exceeded, skipping tag", error))
                i++
                errcnt = 0
                continue
            }
            fmt.Println("Done")
    /*


            
            uidstr := tag.UID()
            fmt.Println("Found tag", uidstr);
            sql := "SELECT rowid, * FROM keys where uid=?"
            for s, err := c.Query(sql, uidstr); err == nil; err = s.Next() {
                var rowid int64
                s.Scan(&rowid, row)     // Assigns 1st column to rowid, the rest to row
                db_acl := row["acl"].(int64)
                if (db_acl & required_acl) == 0 {
                    fmt.Println("Found card ", uidstr , " but ACL not granted")
                    continue
                }
                valid_found = true
                fmt.Println("Access GRANTED to ", uidstr)
                go pulse_gpio(green_led, gpiomap["green_led"].(map[interface{}]interface{})["time"].(int))
                go pulse_gpio(relay, gpiomap["relay"].(map[interface{}]interface{})["time"].(int))
            }
    */

            _ = desfiretag.Disconnect()
            
            // Reset the error counter and increase tag index
            errcnt = 0
            i++
        }
        if !valid_found {
            fmt.Println("Access DENIED")
            go pulse_gpio(red_led, gpiomap["red_led"].(map[interface{}]interface{})["time"].(int))
        }
        // Wait a moment before continuing with fast polling
        time.Sleep(500 * time.Millisecond)
    }
}

