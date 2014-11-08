package main

import (
    "fmt"
    "github.com/fuzxxl/nfc/2.0/nfc"    
    "github.com/fuzxxl/freefare/0.3/freefare"
)

func main() {

	device, error := nfc.Open("")
	if error != nil {
		panic(error)
	}
	tags, error := freefare.GetTags(device)
	if error != nil {
		panic(error)
	}
	for i := 0; i < len(tags); i++ {
		tag := tags[i]
		if (tag.Type() != freefare.DESFire) {
			continue
		}
		fmt.Println(tag.String(), tag.UID())
		desfiretag := tag.(freefare.DESFireTag)
		error := desfiretag.Connect()
		if error != nil {
			panic(error)
		}

		nullkeydata := new([8]byte)
		defaultkey := freefare.NewDESFireDESKey(*nullkeydata)
		error = desfiretag.Authenticate(0,*defaultkey)
		if error != nil {
			panic(error)
		}
		apps, error := desfiretag.ApplicationIds()
		if error != nil {
			panic(error)
		}
		for i := 0; i < len(apps); i++ {
			app := apps[i]
			fmt.Printf("App 0x%x (%d)\n", app.Aid(), app.Aid())
			error := desfiretag.SelectApplication(app)
            if error != nil {
                panic(error)
            }
    		files, error := desfiretag.FileIds()
            if error != nil {
                panic(error)
            }
            fmt.Println(files);
		}
	}
}