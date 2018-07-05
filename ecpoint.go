package dkg

import (
	"crypto/elliptic"
	"math/big"
)

type ECPoint struct {
	X, Y *big.Int
}

func (ecp *ECPoint) Params(a, b *big.Int) *elliptic.CurveParams {

}

func (ecp *ECPoint) IsOnCurve(a *ECPoint) bool {

}

func (ecp *ECPoint) Add(a, b *big.Int) *ECPoint {

}

func (ecp *ECPoint) ScalarMult(a *ECPoint, k *big.Int) *ECPoint {

}

func (ecp *ECPoint) ScalarBaseMult(k *big.Int) *ECPoint {

}
