package dkg

import (
	"crypto/elliptic"
	"math/big"
)

type ECPoint struct {
	X, Y  *big.Int
	curve elliptic.Curve
}

// Params - Returns curve parameters for P256 curve.
func (ecp *ECPoint) Params(a, b *big.Int) *GroupCurveParams {
	return &GroupCurveParams{
		P:       ecp.curve.Params().P,
		N:       ecp.curve.Params().N,
		B:       ecp.curve.Params().B,
		Gx:      ecp.curve.Params().Gx,
		Gy:      ecp.curve.Params().Gy,
		BitSize: ecp.curve.Params().BitSize,
		Name:    ecp.curve.Params().Name,
	}
}

// IsOnCurve - Returns if point `a` is on the ecp curve.
func (ecp *ECPoint) IsOnCurve(a *ECPoint) bool {
	return ecp.curve.IsOnCurve(a.X, a.Y)
}

// Add - Returns addition of ECPoints `a` and `b`.
func (ecp *ECPoint) Add(a, b *ECPoint) *ECPoint {
	sumX, sumY := ecp.curve.Add(a.X, a.Y, b.X, b.Y)
	return &ECPoint{sumX, sumY, ecp.curve}
}

// ScalarMult - Returns multiplication of point `a` by scalar `k`.
func (ecp *ECPoint) ScalarMult(a *ECPoint, k *big.Int) *ECPoint {
	mulX, mulY := ecp.curve.ScalarMult(a.X, a.Y, k.Bytes())
	return &ECPoint{mulX, mulY, ecp.curve}
}

// ScalarBaseMult - Returns multiplication of `ecp` base point by scalar `k`.
func (ecp *ECPoint) ScalarBaseMult(k *big.Int) *ECPoint {
	mulX, mulY := ecp.curve.ScalarBaseMult(k.Bytes())
	return &ECPoint{mulX, mulY, ecp.curve}
}
