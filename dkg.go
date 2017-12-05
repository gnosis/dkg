package dkg

import "errors"
import "crypto/elliptic"
import "math/big"

type ScalarPolynomial []*big.Int

func (p ScalarPolynomial) validate(curve elliptic.Curve) []error {
	if len(p) <= 0 {
		return []error{errors.New("dkg: empty polynomial")}
	}

	var errors []error = nil
	for _, c := range p {
		if c.Sign() == 0 || !isNormalizedScalar(c, curve.Params().N) {
			errors = append(errors, InvalidCurveScalarError{curve, c})
		}
	}
	return errors
}

type node struct {
	curve             elliptic.Curve
	zkParam           *big.Int
	g2x, g2y          *big.Int
	id                *big.Int
	secretPoly1       ScalarPolynomial
	secretPoly2       ScalarPolynomial
	otherParticipants []struct {
		id                 *big.Int
		verificationPoints pointTuple
	}
}

func isNormalizedScalar(x, n *big.Int) bool {
	return x != nil && x.Sign() >= 0 && x.Cmp(n) < 0
}

func NewNode(
	curve elliptic.Curve,
	g2x *big.Int, g2y *big.Int,
	zkParam *big.Int,
	id *big.Int,
	secretPoly1 ScalarPolynomial,
	secretPoly2 ScalarPolynomial,
) (*node, error) {

	if !isNormalizedScalar(g2x, curve.Params().P) ||
		!isNormalizedScalar(g2y, curve.Params().P) ||
		!curve.IsOnCurve(g2x, g2y) {
		return nil, InvalidCurvePointError{curve, g2x, g2y}
	}

	var polyErrors []error = nil
	polyErrors = secretPoly1.validate(curve)
	if len(secretPoly1) != len(secretPoly2) {
		polyErrors = append(polyErrors, InvalidScalarPolynomialLengthError{secretPoly1, secretPoly2})
	}
	if polyErrors != nil {
		return nil, InvalidCurveScalarPolynomialError{curve, secretPoly1, polyErrors}
	}

	polyErrors = secretPoly2.validate(curve)
	if polyErrors != nil {
		return nil, InvalidCurveScalarPolynomialError{curve, secretPoly2, polyErrors}
	}

	return &node{curve, g2x, g2y, zkParam, id, secretPoly1, secretPoly2, nil}, nil
}

func (n *node) PublicKeyPart() (x, y *big.Int) {
	return n.curve.ScalarBaseMult(n.secretPoly1[0].Bytes())
}

type pointTuple []struct{ X, Y *big.Int }

func (n *node) VerificationPoints() pointTuple {
	// curve.add(curve.multiply(curve.G, c1), curve.multiply(G2, c2))
	// for c1, c2 in zip(spoly1, spoly2)
	vpts := make(pointTuple, len(n.secretPoly1))
	for i, c1 := range n.secretPoly1 {
		c2 := n.secretPoly2[i]
		ax, ay := n.curve.ScalarBaseMult(c1.Bytes())
		bx, by := n.curve.ScalarMult(n.g2x, n.g2y, c2.Bytes())
		vpts[i].X, vpts[i].Y = n.curve.Add(ax, ay, bx, by)
	}
	return vpts
}
