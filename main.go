package main

import (
	"fmt"
	"io/ioutil"
	"os"

	"github.com/stsilk/rmf"
)

func main() {

	xmlFile, err := os.Open("example.ckl")
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("Successfully Opened example checklist")
	byteValue, _ := ioutil.ReadAll(xmlFile)

	checklist := rmf.ParseChecklist(byteValue)
	for _, x := range checklist.Asset.Role {
		fmt.Println(x)
	}
	defer xmlFile.Close()
	counts := rmf.CountStatus(checklist)
	fmt.Println(counts)
}
