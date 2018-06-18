package dkg

import (
	"bufio"
	"fmt"
	"io"
)

// func EstablishStream(s net.Stream) {
func EstablishStream(rd io.Reader, wd io.Writer) (rwr *bufio.ReadWriter) {
	fmt.Println("Got a new stream!")

	// // Create a buffer stream for non blocking read and write.
	rw := bufio.NewReadWriter(bufio.NewReader(rd), bufio.NewWriter(wd))

	// go readData(rw)
	// go writeData(rw)
	return rw
	// stream 's' will stay open until you close it (or the other side closes it).
}

func ReadData(rw *bufio.ReadWriter) {
	fmt.Println("Reading")
	buf := make([]byte, 4)
	_, err := rw.Read(buf)
	if err != nil {
		panic(err)
	}
	fmt.Printf("%q\n", buf)
	// for {
	// 	str, _ := rw.ReadString('\n')

	// 	fmt.Println(str)

	// }
}

func WriteData(rw *bufio.ReadWriter) {
	fmt.Println("Writing")
	buf := []byte("efgh")
	_, err := rw.Write(buf)
	if err != nil {
		panic(err)
	}
	err = rw.Flush()
	if err != nil {
		panic(err)
	}
	// stdReader := bufio.NewReader(os.Stdin)

	// for {
	// 	fmt.Print("> ")
	// 	sendData, err := stdReader.ReadString('\n')

	// 	if err != nil {
	// 		panic(err)
	// 	}

	// 	rw.WriteString(fmt.Sprintf("%s\n", sendData))
	// 	rw.Flush()
	// }

}
