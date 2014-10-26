package main

import (
    "fmt"
    "github.com/fuzxxl/nfc/2.0/nfc"    
    "github.com/fuzxxl/freefare/0.3/freefare"    
    "code.google.com/p/go-sqlite/go1/sqlite3"
    "time"
    "gopkg.in/yaml.v2"
    "io/ioutil"
)

func heartbeat() {
    for {
        time.Sleep(2000 * time.Millisecond)
        fmt.Println("Dunka-dunk")
    }
}


func main() {
    d, err := nfc.Open("");
    if err != nil {
        panic(err);
    }

    appdata, err := ioutil.ReadFile("apps.yaml");
    if err != nil {
        panic(err);
    }
    appmap := make(map[interface{}]interface{});
    err = yaml.Unmarshal([]byte(appdata), &appmap);
    if err != nil {
        panic(err);
    }
    required_acl := int64(appmap["aclapp"].(map[interface{}]interface{})["require_acl"].(int))

    c, err := sqlite3.Open("keys.db")
    if err != nil {
        panic(err);
    }
    row := make(sqlite3.RowMap)

    go heartbeat()
    // mainlopp
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
        for i := 0; i < len(tags); i++ {
            tag := tags[i]
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
            }
        }
        if !valid_found {
            fmt.Println("Access DENIED")
        }
        // Wait a moment before continuing with fast polling
        time.Sleep(500 * time.Millisecond)
    }
}
