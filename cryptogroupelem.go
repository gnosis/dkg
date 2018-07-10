package dkg

import (
	"math/big"
)

// CryptoGroupElem - Interface for dkg protocol use with multiple curves + bilinear pairings
type CryptoGroupElem interface {
	N() *big.Int        // the order of the base point
	G() CryptoGroupElem // (x,y) of the base point
	IsOnCurve(a *CryptoGroupElem) bool
	Add(a, b *CryptoGroupElem) (e *CryptoGroupElem)
	ScalarBaseMult(k *big.Int) (e *CryptoGroupElem)
	ScalarMult(a *CryptoGroupElem, k *big.Int) (e *CryptoGroupElem)
}

// GroupCurveParams - Interface struct for curve parameters
// type GroupCurveParams struct {

// }
