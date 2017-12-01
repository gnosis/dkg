package dkg

import "hash"
import "crypto/elliptic"
import "math/big"

type Node struct {
	curve    elliptic.Curve
	hash     hash.Hash
	g2x, g2y *big.Int
	private  *big.Int
}

func IsNormalizedScalar(n, x *big.Int) bool {
	return x != nil && x.Sign() >= 0 && x.Cmp(n) < 0
}

func NewNode(
	curve elliptic.Curve,
	hash hash.Hash,
	g2x *big.Int, g2y *big.Int,
	private *big.Int,
) (*Node, error) {

	if !IsNormalizedScalar(curve.Params().P, g2x) ||
		!IsNormalizedScalar(curve.Params().P, g2y) ||
		!curve.IsOnCurve(g2x, g2y) {
		return nil, InvalidCurvePointError{curve, g2x, g2y}
	}
	if !IsNormalizedScalar(curve.Params().N, private) {
		return nil, InvalidCurveScalarError{curve, private}
	}
	return &Node{curve, hash, g2x, g2y, private}, nil
}

func (n *Node) PublicKey() (x, y *big.Int) {
	return n.curve.ScalarBaseMult(n.private.Bytes())
}
