package dkg

import (
	// "crypto/elliptic"
	"math/big"
)

type ECPoint struct {
	X, Y *big.Int
}

func (e *ECPoint) Params(a, b *big.Int) {

}

func (e *ECPoint) IsOnCurve(a, b *big.Int) {

}

func (e *ECPoint) Add(a, b *big.Int) {

}

func (e *ECPoint) ScalarMult(a, b *big.Int) {

}

func (e *ECPoint) ScalarBaseMult(a, b *big.Int) {

}
