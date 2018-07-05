package dkg

import (
	"crypto/elliptic"
	"math/big"
)

type ECPoint struct {
	X, Y *big.Int
}

func (e *ECPoint) Params(a, b *big.Int) *elliptic.CurveParams {

}

func (e *ECPoint) IsOnCurve(a, b *big.Int) bool {

}

func (e *ECPoint) Add(a, b *big.Int) *ECPoint {

}

func (e *ECPoint) ScalarMult(a, b *big.Int) *ECPoint {

}

func (e *ECPoint) ScalarBaseMult(a, b *big.Int) *ECPoint {

}
