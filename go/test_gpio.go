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
    "gopkg.in/yaml.v2"
    "io/ioutil"
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
    d, err := nfc.Open("");
    if err != nil {
        panic(err);
    }

    gpiodata, err := ioutil.ReadFile("gpio.yaml");
    if err != nil {
        panic(err);
    }
    gpiomap := make(map[interface{}]interface{});
    err = yaml.Unmarshal([]byte(gpiodata), &gpiomap);
    if err != nil {
        panic(err);
    }

    c, err := sqlite3.Open("keys.db")
    if err != nil {
        panic(err);
    }
    row := make(sqlite3.RowMap)

    go heartbeat()

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
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt)
	go func() {
		for _ = range ch {
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
                fmt.Println("Access GRANTED to ", uidstr)
                go pulse_gpio(green_led, gpiomap["green_led"].(map[interface{}]interface{})["time"].(int))
                go pulse_gpio(relay, gpiomap["relay"].(map[interface{}]interface{})["time"].(int))
            }
        }
        if !valid_found {
            fmt.Println("Access DENIED")
            go pulse_gpio(red_led, gpiomap["red_led"].(map[interface{}]interface{})["time"].(int))
        }
        // Wait a moment before continuing with fast polling
        time.Sleep(500 * time.Millisecond)
    }
}
