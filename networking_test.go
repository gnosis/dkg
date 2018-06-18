package dkg

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

// func TestBasicNetworking(t *testing.T) {
// 	fmt.Println("Starting")
// 	reader := strings.NewReader("abcd\n")
// 	writer := new(bytes.Buffer)
// 	EstablishStream(reader, writer)
// 	fmt.Println("ended")
// }

func TestBasicReadWriteMessage(t *testing.T) {
	s := strings.NewReader("abcd")
	w := new(bytes.Buffer)
	rw := EstablishStream(s, w)

	ReadData(rw)

	WriteData(rw)
	fmt.Println(w.String())

}
