package dkg

import (
	"math/big"
)

type SecretSharesMessage struct {
	From     *big.Int
	To       *big.Int
	S1x, S1y *big.Int
	S2x, S2y *big.Int
}

type ComplaintMessage struct {
	Accusor *big.Int
	Accused *big.Int
}

type PublicPointsMessage struct {
	Player *big.Int
	Points PointTuple
}

// func (t *SecretSharesMessage) Print(args *int, reply *bool) error {
// 	*reply = true
// 	return nil
// }
