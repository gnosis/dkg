package dkg

import "hash"
import "crypto/elliptic"
import "math/big"

type ScalarPolynomial []*big.Int

func (p ScalarPolynomial) validate(curve elliptic.Curve) error {
	for _, c := range p {
		if !isNormalizedScalar(c, curve.Params().N) {
			return InvalidCurveScalarError{curve, c}
		}
	}
	return nil
}

type node struct {
	curve       elliptic.Curve
	hash        hash.Hash
	g2x, g2y    *big.Int
	secretPoly1 ScalarPolynomial
	secretPoly2 ScalarPolynomial
}

func isNormalizedScalar(x, n *big.Int) bool {
	return x != nil && x.Sign() >= 0 && x.Cmp(n) < 0
}

func NewNode(
	curve elliptic.Curve,
	hash hash.Hash,
	g2x *big.Int, g2y *big.Int,
	secretPoly1 ScalarPolynomial,
	secretPoly2 ScalarPolynomial,
) (*node, error) {

	if !isNormalizedScalar(g2x, curve.Params().P) ||
		!isNormalizedScalar(g2y, curve.Params().P) ||
		!curve.IsOnCurve(g2x, g2y) {
		return nil, InvalidCurvePointError{curve, g2x, g2y}
	}

	if err := secretPoly1.validate(curve); err != nil {
		return nil, err
	}
	if err := secretPoly2.validate(curve); err != nil {
		return nil, err
	}

	return &node{curve, hash, g2x, g2y, secretPoly1, secretPoly2}, nil
}

func (n *node) PublicKey() (x, y *big.Int) {
	return n.curve.ScalarBaseMult(n.secretPoly1[0].Bytes())
}
