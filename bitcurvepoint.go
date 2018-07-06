package dkg

import (
	"math/big"

	"github.com/ethereum/go-ethereum/crypto/secp256k1"
)

type BitCurvePoint struct {
	X, Y  *big.Int
	curve secp256k1.BitCurve
}

// Params - Returns curve parameters for P256 curve.
func (bcp *BitCurvePoint) Params(a, b *big.Int) *GroupCurveParams {
	return &GroupCurveParams{
		P:       bcp.curve.Params().P,
		N:       bcp.curve.Params().N,
		B:       bcp.curve.Params().B,
		Gx:      bcp.curve.Params().Gx,
		Gy:      bcp.curve.Params().Gy,
		BitSize: bcp.curve.Params().BitSize,
		Name:    bcp.curve.Params().Name,
	}
}

// IsOnCurve - Returns if point `a` is on the bcp curve.
func (bcp *BitCurvePoint) IsOnCurve(a *BitCurvePoint) bool {
	return bcp.curve.IsOnCurve(a.X, a.Y)
}

// Add - Returns addition of BitCurvePoints `a` and `b`.
func (bcp *BitCurvePoint) Add(a, b *BitCurvePoint) *BitCurvePoint {
	sumX, sumY := bcp.curve.Add(a.X, a.Y, b.X, b.Y)
	return &BitCurvePoint{sumX, sumY, bcp.curve}
}

// ScalarMult - Returns multiplication of point `a` by scalar `k`.
func (bcp *BitCurvePoint) ScalarMult(a *BitCurvePoint, k *big.Int) *BitCurvePoint {
	mulX, mulY := bcp.curve.ScalarMult(a.X, a.Y, k.Bytes())
	return &BitCurvePoint{mulX, mulY, bcp.curve}
}

// ScalarBaseMult - Returns multiplication of `bcp` base point by scalar `k`.
func (bcp *BitCurvePoint) ScalarBaseMult(k *big.Int) *BitCurvePoint {
	mulX, mulY := bcp.curve.ScalarBaseMult(k.Bytes())
	return &BitCurvePoint{mulX, mulY, bcp.curve}
}
