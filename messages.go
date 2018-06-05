package dkg

import (
	"bytes"
	"encoding/gob"
	"log"
	"math/big"
)

type MessageType int

const (
	Distribution MessageType = iota
	Verification MessageType = iota
	Check        MessageType = iota
	Generation   MessageType = iota
)

type SecretSharesMessage struct {
	From     *big.Int
	To       *big.Int
	S1x, S1y *big.Int
	S2x, S2y *big.Int
}

func NewSecretSharesMessage(
	From *big.Int,
	To *big.Int,
	S1x *big.Int, S1y *big.Int,
	S2x *big.Int, S2y *big.Int,
) *SecretSharesMessage {
	//check message has valid id
	//determine private or public
	//determine complaint or no complaint
	//ensure message type correlates with above
	return &SecretSharesMessage{
		From, To, S1x, S1y, S2x, S2y,
	}
}

func EncodeSecretSharesMessage(
	network *bytes.Buffer,
	message *SecretSharesMessage,
) bool {
	enc := gob.NewEncoder(network)
	err := enc.Encode(message)
	if err != nil {
		log.Fatal("encode error:", err)
		return false
	} else {
		log.Println("encode success")
		return true
	}
}

func DecodeSecretSharesMessage(
	network *bytes.Buffer,
) *SecretSharesMessage {
	dec := gob.NewDecoder(network)
	var decoded SecretSharesMessage
	err := dec.Decode(&decoded)
	if err != nil {
		log.Fatal("decode error ", err)
		return &decoded
	} else {
		log.Println("decode success")
		return &decoded
	}
}

// func broadCastMessage(message Message) bool {
// 	//ToDO
// }

// func sendMessage(receiver int, message Message) bool {
// 	//ToDO
// }

// func receiveMessage(message Message) bool {
// 	//ToDO
// }
