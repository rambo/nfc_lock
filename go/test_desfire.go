package main

import "fmt"
import "github.com/fuzxxl/nfc/2.0/nfc"
import "github.com/fuzxxl/freefare/0.3/freefare"

func main() {

	device, error := nfc.Open("pn532_uart:/dev/ttyUSB0:115200")
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
		fmt.Println(tag.String())
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
			fmt.Println(app)
		}
	}
}