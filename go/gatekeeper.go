package main

import (
    "fmt"
    /*
    "os"
    "os/signal"
    */
    "runtime"
    "errors"
    "time"
    "encoding/hex"
    "encoding/binary"
    "database/sql"
    "github.com/fuzxxl/nfc/2.0/nfc"    
    "github.com/fuzxxl/freefare/0.3/freefare"
    _ "github.com/mattn/go-sqlite3"
    //"github.com/davecheney/gpio"
    "./keydiversification"
    "./helpers"
    // "github.com/davecheney/profile"
)

func heartbeat() {
    for {
        time.Sleep(2000 * time.Millisecond)
        fmt.Println("Dunka-dunk")
    }
}

/*
func pulse_gpio(pin gpio.Pin, ms int) {
    pin.Set()
    time.Sleep(time.Duration(ms) * time.Millisecond)
    pin.Clear()
}

func clear_and_close(pin gpio.Pin) {
    pin.Clear()
    pin.Close()
}
*/

// Use structs to pass data around so I can refactor 
type AppInfo struct {
    aid freefare.DESFireAid
    aidbytes []byte
    sysid []byte
    acl_read_base []byte
    acl_write_base []byte
    acl_file_id byte
}

type KeyChain struct {
    uid_read_key_id byte
    acl_read_key_id byte
    acl_write_key_id byte

    uid_read_key *freefare.DESFireKey
    acl_read_key *freefare.DESFireKey
    acl_write_key *freefare.DESFireKey
}

// To pass multiple values over a channel
type TagResult struct {
    is_valid bool
    err error
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
    acl_read_bytes, err := keydiversification.AES128(appinfo.acl_read_base, appinfo.aidbytes, realuid, appinfo.sysid)
    if err != nil {
        return err
    }
    acl_write_bytes, err := keydiversification.AES128(appinfo.acl_write_base, appinfo.aidbytes, realuid, appinfo.sysid)
    if err != nil {
        return err
    }
    keychain.acl_read_key = helpers.Bytes2aeskey(acl_read_bytes)
    keychain.acl_write_key = helpers.Bytes2aeskey(acl_write_bytes)
    return nil
}

func update_acl_file(desfiretag *freefare.DESFireTag, newdata *[]byte) error {
    fmt.Print("Re-auth with ACL write key, ")
    err := desfiretag.Authenticate(keychain.acl_write_key_id,*keychain.acl_write_key)
    if err != nil {
        return err
    }
    fmt.Println("Done")

    fmt.Print("Overwriting ACL data file, ")
    byteswritten, err := desfiretag.WriteData(appinfo.acl_file_id, 0, *newdata)
    if err != nil {
        return err
    }
    if (byteswritten < 4) {
        fmt.Println(fmt.Sprintf("WARNING: WriteData wrote %d bytes, 4 expected", byteswritten))
    }
    fmt.Println("Done")
    return nil
}

func check_revoked(db *sql.DB, realuid_str string) (bool, error) {
    revoked_found := false
    stmt, err := db.Prepare("SELECT rowid FROM revoked where uid=?")
    if err != nil {
        return true, err
    }
    defer stmt.Close()
    rows, err := stmt.Query(realuid_str)
    if err != nil {
        return true, err
    }
    defer rows.Close()    
    for rows.Next() {
        revoked_found = true
        var rowid int64
        rows.Scan(&rowid)     // Assigns 1st column to rowid, the rest to row
        fmt.Println(fmt.Sprintf("WARNING: Found REVOKED key %s on row %d", realuid_str, rowid))

        // TODO: Publish a ZMQ message or something

    }
    return revoked_found, nil
}

func read_and_parse_acl_file(desfiretag *freefare.DESFireTag) (uint32, error) {

    aclbytes := make([]byte, 4)
    fmt.Print("Reading ACL data file, ")
    bytesread, err := desfiretag.ReadData(appinfo.acl_file_id, 0, aclbytes)
    if err != nil {
        return 0, err
    }
    if (bytesread < 4) {
        fmt.Println(fmt.Sprintf("WARNING: ReadData read %d bytes, 4 expected", bytesread))
    }
    acl64, n := binary.Uvarint(aclbytes)
    if n <= 0 {
        return 0, errors.New(fmt.Sprintf("ERROR: binary.Uvarint returned %d, skipping tag", n))
    }
    fmt.Println("Done")
    return uint32(acl64), nil
}

func get_db_acl(db *sql.DB, realuid_str string) (uint32, error) {
    stmt, err := db.Prepare("SELECT rowid,acl FROM keys where uid=?")
    if err != nil {
        return 0, err
    }
    defer stmt.Close()
    rows, err := stmt.Query(realuid_str)
    if err != nil {
        return 0, err
    }
    defer rows.Close()    
    for rows.Next() {
        var rowid int64
        var acl int64
        rows.Scan(&rowid, &acl)
        return uint32(acl), nil
    }
    return 0, errors.New(fmt.Sprintf("UID not found"))
}

func check_tag_channel(desfiretag *freefare.DESFireTag, db *sql.DB, required_acl uint32, ch chan TagResult) {
    result, err := check_tag(desfiretag, db, required_acl)
    ch <- TagResult{result, err}
    close(ch)
}

func check_tag(desfiretag *freefare.DESFireTag, db *sql.DB, required_acl uint32) (bool, error) {
    const errlimit = 3
    var err error = nil
    var realuid_str string
    var realuid []byte
    acl := uint32(0)
    db_acl := uint32(0)
    revoked_found := false
    errcnt := 0
    connected := false

    // TODO: Add a timeout for all of this, if not done in 1s or so we have a problem...    
RETRY:
    if err != nil {
        // TODO: Retry only on RF-errors
        errcnt++
        if errcnt > errlimit {
            fmt.Println(fmt.Sprintf("failed (%s), retry-limit exceeded (%d/%d), skipping tag", err, errcnt, errlimit))
            goto FAIL
        }
        fmt.Println(fmt.Sprintf("failed (%s), retrying (%d)", err, errcnt))
    }
    if connected {
        _ = desfiretag.Disconnect()
    }

    // Connect to this tag
    fmt.Print(fmt.Sprintf("Connecting to %s, ", desfiretag.UID()))
    err = desfiretag.Connect()
    if err != nil {
        goto RETRY
    }
    fmt.Println("done")
    connected = true

    fmt.Print(fmt.Sprintf("Selecting application %d, ", appinfo.aid.Aid()))
    err = desfiretag.SelectApplication(appinfo.aid);
    if err != nil {
        goto RETRY
    }
    fmt.Println("Done")

    fmt.Print("Authenticating, ")
    err = desfiretag.Authenticate(keychain.uid_read_key_id,*keychain.uid_read_key)
    if err != nil {
        goto RETRY
    }
    fmt.Println("Done")

    // Get card real UID        
    realuid_str, err = desfiretag.CardUID()
    if err != nil {
        // TODO: Retry only on RF-errors
        goto RETRY
    }
    realuid, err = hex.DecodeString(realuid_str)
    if err != nil {
        fmt.Println(fmt.Sprintf("ERROR: Failed to parse real UID (%s), skipping tag", err))
        goto FAIL
    }
    fmt.Println("Got real UID:", hex.EncodeToString(realuid));

    // Calculate the diversified keys
    err = recalculate_diversified_keys(realuid)
    if err != nil {
        fmt.Println(fmt.Sprintf("ERROR: Failed to get diversified ACL keys (%s), skipping tag", err))
        goto FAIL
    }

    // Check for revoked key
    revoked_found, err = check_revoked(db, realuid_str)
    if err != nil {
        fmt.Println(fmt.Sprintf("check_revoked returned err (%s)", err))
        revoked_found = true
    }
    if revoked_found {
        // Null the ACL file on card
        nullaclbytes := make([]byte, 4)
        // Just go to fail even if this write fails
        _ = update_acl_file(desfiretag, &nullaclbytes)
        goto FAIL
    }

    fmt.Print("Re-auth with ACL read key, ")
    err = desfiretag.Authenticate(keychain.acl_read_key_id,*keychain.acl_read_key)
    if err != nil {
        goto RETRY
    }
    fmt.Println("Done")

    acl, err = read_and_parse_acl_file(desfiretag)
    if err != nil {
        goto RETRY
    }
    //fmt.Println("DEBUG: acl:", acl)

    // Get (possibly updated) ACL from DB, if returns error then UID is not known
    db_acl, err = get_db_acl(db, realuid_str)
    if err != nil {
        // No match
        fmt.Println(fmt.Sprintf("WARNING: key %s, not found in DB", realuid_str))
        // TODO: Should we null the ACL file just in case, because any key that is personalized but not either valid or revoked is in a weird limbo
        goto FAIL
    }

    // Check for ACL update
    if (acl != db_acl) {
        fmt.Println(fmt.Sprintf("NOTICE: card ACL (%x) does not match DB (%x), ", acl, db_acl))

        // Update the ACL file on card
        newaclbytes := make([]byte, 4)
        n := binary.PutUvarint(newaclbytes, uint64(db_acl))
        if (n < 0) {
            fmt.Println(fmt.Sprintf("binary.PutUvarint returned %d, skipping tag", n))
            goto FAIL
        }
        err := update_acl_file(desfiretag, &newaclbytes)
        if err != nil {
            goto RETRY
        }
    }

    // Now check the ACL match
    if (db_acl & required_acl) == 0 {
        fmt.Println(fmt.Sprintf("NOTICE: Found valid key %s, but ACL (%x) not granted", realuid_str, required_acl))
        // TODO: Publish a ZMQ message or something
        goto FAIL
    }    

    fmt.Println(fmt.Sprintf("SUCCESS: Access granted to %s with ACL (%x)", realuid_str, db_acl))
    return true, nil
FAIL:
    if connected {
        _ = desfiretag.Disconnect()
    }
    return false, err
}

func main() {
    /*
    cfg := profile.Config {
            MemProfile: true,
            NoShutdownHook: true, // do not hook SIGINT
    }
    // p.Stop() must be called before the program exits to  
    // ensure profiling information is written to disk.
    p := profile.Start(&cfg)
    defer p.Stop()
    */

    // TODO: configure this somewhere
    required_acl := uint32(1)

    init_appinfo()

    /*
    gpiomap, err := helpers.LoadYAMLFile("gpio.yaml")
    if err != nil {
        panic(err)
    }
    */

    db, err := sql.Open("sqlite3", "./keys.db")
    if err != nil {
        panic(err)
    }
    defer db.Close()

    // Open NFC device
    nfcd, err := nfc.Open("");
    if err != nil {
        panic(err);
    }
    //defer nfcd.Close()

    // Start heartbeat goroutine
    //go heartbeat()

    /*
    // Get open GPIO pins for our outputs
    green_led, err := gpio.OpenPin(gpiomap["green_led"].(map[interface{}]interface{})["pin"].(int), gpio.ModeOutput)
    if err != nil {
        panic(err)
    }
    red_led, err := gpio.OpenPin(gpiomap["red_led"].(map[interface{}]interface{})["pin"].(int), gpio.ModeOutput)
    if err != nil {
        panic(err)
    }
    relay, err := gpio.OpenPin(gpiomap["relay"].(map[interface{}]interface{})["pin"].(int), gpio.ModeOutput)
    if err != nil {
        panic(err)
    }
    */
    // turn the leds off on exit
    /*
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
    */

    fmt.Println("Starting mainloop")
    // mainloop
    for {
        runtime.GC()
        // Poll for tags
        var tags []freefare.Tag
        for {
            tags, err = freefare.GetTags(nfcd)
            if err != nil {
                continue
            }
            if len(tags) > 0 {
                break
            }
            time.Sleep(100 * time.Millisecond)
            //fmt.Println("...polling")
        }

        valid_found := false
        for i := 0; i < len(tags); i++ {
            tag := tags[i]
            if (tag.Type() != freefare.DESFire) {
                fmt.Println(fmt.Sprintf("Non-DESFire tag %s skipped", tag.UID()))
                continue
            }
            desfiretag := tag.(freefare.DESFireTag)

            ch := make(chan TagResult, 1)
            go check_tag_channel(&desfiretag, db, required_acl, ch)
            select {
                case res, ok := <-ch:
                    if !ok {
                        // Channel closed
                    } else {
                        if res.is_valid {
                            valid_found = true
                        }
                    }
                case <-time.After(time.Second * 1):
                    fmt.Println("WARNING: Timeout while checking tag")
                    // TODO: Do we even need this, probably not...
                    // _ = desfiretag.Disconnect()
            }
        }

        if !valid_found {
            fmt.Println("Access DENIED")
            //go pulse_gpio(red_led, gpiomap["red_led"].(map[interface{}]interface{})["time"].(int))
        } else {
            fmt.Println("Blinkety-blink")
            /*
            go pulse_gpio(green_led, gpiomap["green_led"].(map[interface{}]interface{})["time"].(int))
            go pulse_gpio(relay, gpiomap["relay"].(map[interface{}]interface{})["time"].(int))
            */
        }

        // Run GC at this time
        //runtime.GC()
        // Wait a moment before continuing with fast polling
        time.Sleep(500 * time.Millisecond)

    }
}

