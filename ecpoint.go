package dkg

import (
	"math/big"
)

type ECPoint struct {
	X, Y *big.Int
}
