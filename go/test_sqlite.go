package main

import (
    "fmt"
    "github.com/fuzxxl/nfc/2.0/nfc"    
    "github.com/fuzxxl/freefare/0.3/freefare"    
    "code.google.com/p/go-sqlite/go1/sqlite3"
    "time"
)

func main() {
    c, err := sqlite3.Open("keys.db")
    if err != nil {
        panic(err);
    }
    row := make(sqlite3.RowMap)

    d, err := nfc.Open("");
    if err != nil {
        panic(err);
    }

    var tags []freefare.Tag
    for {
        tags, err := freefare.GetTags(d);
        if err != nil {
            panic(err);
        }
        if len(tags) > 0 {
            break;
        }
        time.Sleep(100 * time.Millisecond)
        //fmt.Println("...polling")
    }
    fmt.Println(tags);
    valid_found := false
    for i := 0; i < len(tags); i++ {
        tag := tags[i]
        uidstr := tag.UID()
        sql := "SELECT rowid, * FROM keys where uid=?"
        for s, err := c.Query(sql, uidstr); err == nil; err = s.Next() {
            var rowid int64
            s.Scan(&rowid, row)     // Assigns 1st column to rowid, the rest to row
            fmt.Println(rowid, row)
            valid_found = true
        }
    }
    if !valid_found {
        fmt.Println("NO ACCESS")
    }
}
