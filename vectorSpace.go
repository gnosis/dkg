package dkg

import (
	"crypto/elliptic"
	"math/big"
)

type VectorSpace interface {
	Params() *elliptic.CurveParams
	IsOnCurve(x, y *big.Int) bool
	Add(x1, y1, x2, y2 *big.Int) (*big.Int, *big.Int)
	Double(x1, y1 *big.Int) (*big.Int, *big.Int)
	ScalarBaseMult(k []byte) (*big.Int, *big.Int)
	ScalarMult(Bx, By *big.Int, k []byte) (*big.Int, *big.Int)
}
