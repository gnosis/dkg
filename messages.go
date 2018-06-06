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
