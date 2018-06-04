package dkg

import (
	"math/big"
)

type MessageType int

const (
	Distribution MessageType = iota
	Verification MessageType = iota
	Check        MessageType = iota
	Generation   MessageType = iota
)

type Message struct {
	mType     MessageType
	id        *big.Int
	sx, sy    *big.Int // private info
	p         *big.Int // public info
	A         *big.Int // public key
	i, j      int      //
	complaint bool
	private   bool
}

func NewMessage(
	_mType MessageType,
	id *big.Int,
	sx *big.Int, sy *big.Int,
	p *big.Int,
	A *big.Int,
	i int, j int,
	complaint bool,
	private bool,
) (*message, error) {
	//check message has valid id
	//determine private or public
	//determine complaint or no complaint
	//ensure message type correlates with above
	return nil, &message{}
}

func broadCastMessage(message Message) bool {
	//TODO
}

func sendMessage(receiver int, message Message) bool {
	//TODO
}

func receiveMessage(message Message) bool {
	//TODO
}
