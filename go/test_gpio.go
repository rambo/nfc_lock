package main

import (
    "fmt"
	"os"
	"os/signal"
    "github.com/fuzxxl/nfc/2.0/nfc"    
    "github.com/fuzxxl/freefare/0.3/freefare"    
    "code.google.com/p/go-sqlite/go1/sqlite3"
    "time"
    "github.com/davecheney/gpio"
    "github.com/davecheney/gpio/rpi"
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

    c, err := sqlite3.Open("keys.db")
    if err != nil {
        panic(err);
    }
    row := make(sqlite3.RowMap)

    go heartbeat()

	// set GPIO21 ie the last pin on b+ to output mode
	green_pin, err := gpio.OpenPin(21, gpio.ModeOutput)
	if err != nil {
		fmt.Printf("Error opening pin! %s\n", err)
		return
	}

	// turn the led off on exit
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt)
	go func() {
		for _ = range ch {
			fmt.Printf("\nClearing and unexporting the pin.\n")
			green_pin.Clear()
			green_pin.Close()
			os.Exit(0)
		}
	}()

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
                fmt.Println(rowid, row)
                valid_found = true
            }
        }
        if valid_found {
            // TODO: run relay in subroutine
            fmt.Println("Access GRANTED")
            go func() {
                green_pin.Set()
                fmt.Println("green ON")
                time.Sleep(2000 * time.Millisecond)
                green_pin.Clear()
                fmt.Println("green OFF")
            }()
        } else {
            fmt.Println("Access DENIED")
        }
        // Wait a moment before continuing with fast polling
        time.Sleep(500 * time.Millisecond)
    }
}
