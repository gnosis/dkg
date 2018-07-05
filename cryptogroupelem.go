package dkg

import (
	"math/big"
)

// CryptoGroupElem - Interface for dkg protocol use with multiple curves + bilinear pairings
type CryptoGroupElem interface {
	Params() *GroupCurveParams
	IsOnCurve(a *CryptoGroupElem) bool
	Add(a, b *CryptoGroupElem) (e *CryptoGroupElem)
	ScalarBaseMult(k *big.Int) (e *CryptoGroupElem)
	ScalarMult(a *CryptoGroupElem, k *big.Int) (e *CryptoGroupElem)
}

// GroupCurveParams - Interface struct for curve parameters
type GroupCurveParams struct {
	P       *big.Int // the order of the underlying field
	N       *big.Int // the order of the base point
	B       *big.Int // the constant of the curve equation
	Gx, Gy  *big.Int // (x,y) of the base point
	BitSize int      // the size of the underlying field
	Name    string   // the canonical name of the curve
}
