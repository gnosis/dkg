package main

import (
	"bufio"
	"fmt"
	"os"
)

// func handleStream(s net.Stream) {
// 	log.Println("Got a new stream!")

// 	// Create a buffer stream for non blocking read and write.
// 	rw := bufio.NewReadWriter(bufio.NewReader(s), bufio.NewWriter(s))

// 	go readData(rw)
// 	go writeData(rw)

// 	// stream 's' will stay open until you close it (or the other side closes it).
// }
// func readData(rw *bufio.ReadWriter) {
// 	for {
// 		str, _ := rw.ReadString('\n')

// 		if str == "" {
// 			return
// 		}
// 		if str != "\n" {
// 			// Green console colour: 	\x1b[32m
// 			// Reset console colour: 	\x1b[0m
// 			fmt.Printf("\x1b[32m%s\x1b[0m> ", str)
// 		}

// 	}
// }

// func writeData(rw *bufio.ReadWriter) {
// 	stdReader := bufio.NewReader(os.Stdin)

// 	for {
// 		fmt.Print("> ")
// 		sendData, err := stdReader.ReadString('\n')

// 		if err != nil {
// 			panic(err)
// 		}

// 		rw.WriteString(fmt.Sprintf("%s\n", sendData))
// 		rw.Flush()
// 	}

// }

func main() {
	w := bufio.NewWriter(os.Stdout)
	fmt.Fprint(w, "Hello, ")
	fmt.Fprint(w, "world!\n")
	w.Flush() // Don't forget to flush!
}
