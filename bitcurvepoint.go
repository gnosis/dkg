package dkg

import (
	"crypto/elliptic"
	"math/big"
	// "github.com/ethereum/go-ethereum/crypto/secp256k1"
)

type BitCurvePoint struct {
	X, Y *big.Int
}

func (bcp *BitCurvePoint) Params() *elliptic.CurveParams {

}

func (bcp *BitCurvePoint) IsOnCurve(a *BitCurvePoint) bool {

}

func (bcp *BitCurvePoint) Add(a, b *big.Int) *BitCurvePoint {

}

func (bcp *BitCurvePoint) ScalarMult(a *BitCurvePoint, k *big.Int) *BitCurvePoint {

}

func (bcp *BitCurvePoint) ScalarBaseMult(k *big.Int) *BitCurvePoint {

}
