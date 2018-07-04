package dkg

import (
	"math/big"
)

// CryptoGroupElem - Interface for dkg protocol use with multiple curves + bilinear pairings
type CryptoGroupElem interface {
	IsOnCurve(a CryptoGroupElem) bool
	Add(a, b CryptoGroupElem) (e CryptoGroupElem)
	ScalarBaseMult(k big.Int) (e CryptoGroupElem)
	ScalarMult(a CryptoGroupElem, k big.Int) (e CryptoGroupElem)
}
