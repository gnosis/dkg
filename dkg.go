// Package dkg provides methods for distributed key generation.
package dkg

import (
	"crypto/cipher"
	"errors"
	"time"

	"github.com/dedis/kyber"
)

// ScalarPolynomial represents polynomials of scalars. It contains coefficients
// from the finite field under the vector space. Coefficient zero represents the constant
// term, coefficient one the linear term's coefficient, two the quadratic, etc.
type ScalarPolynomial []kyber.Scalar

// validate ensures all elements of a scalar polynomial are compatible with a given
// finite field associated with the vector space given.
func (p ScalarPolynomial) validate(curve kyber.Group) []error {
	if len(p) <= 0 {
		return []error{errors.New("dkg: empty polynomial")}
	}

	var errors []error
	for _, c := range p {
		if c.Equal(curve.Scalar().Zero()) {
			errors = append(errors, InvalidCurveScalarError{curve, c})
		}
	}
	return errors
}

// node represents a dkg node
type node struct {
	// The vector space underlying the protocol. Typically will be an elliptic curve.
	curve kyber.Group
	// A second element of the vector space for which the scalar k in the relation k * G = G2 is unknown.
	g2 kyber.Point
	// A zero knowledge parameter agreed upon within the DKG group for proving possession of secrets
	// that have a corresponding vector
	zkParam kyber.Scalar
	// A timeout for communications in the protocol
	timeout time.Duration

	// The ID associated with a node. Must be a scalar from the finite field underlying the vector space
	id kyber.Scalar
	// The first secret polynomial for the node
	secretPoly1 ScalarPolynomial
	// The second secret polynomial for the node
	secretPoly2 ScalarPolynomial

	// This node's view of other nodes in the protocol
	otherParticipants []Participant
}

// NewNode constructs a new node for DKG given some configuration variables.
func NewNode(
	curve kyber.Group,
	g2 kyber.Point,
	zkParam kyber.Scalar,
	timeout time.Duration,

	id kyber.Scalar,
	secretPoly1 ScalarPolynomial,
	secretPoly2 ScalarPolynomial,
) (*node, error) {

	if g2.Equal(curve.Point().Null()) {
		return nil, InvalidCurvePointError{curve, g2}
	}

	var polyErrors []error
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

	return &node{
		curve, g2, zkParam, timeout,
		id, secretPoly1, secretPoly2,
		nil,
	}, nil
}

func (n *node) ScalarBaseMult(s kyber.Scalar) kyber.Point {
	return n.curve.Point().Mul(s, n.curve.Point().Base())
}

// PublicKeyPart retrieves the vector related to the constant term of a node's first secret polynomial.
func (n *node) PublicKeyPart() (p kyber.Point) {
	return n.ScalarBaseMult(n.secretPoly1[0])
}

// PointTuple represents a set of vectors.
type PointTuple []kyber.Point

// VerificationPoints retrives a set of vectors which may be used to verify that secret shares
// sent to a node are legitimate.
func (n *node) VerificationPoints() PointTuple {
	// [c1 * G + c2 * G2 for c1, c2 in zip(spoly1, spoly2)]
	vpts := make(PointTuple, len(n.secretPoly1))
	for i, c1 := range n.secretPoly1 {
		c2 := n.secretPoly2[i]
		a := n.ScalarBaseMult(c1)
		b := n.curve.Point().Mul(c2, n.g2)
		vpts[i] = n.curve.Point().Add(a, b)
	}
	return vpts
}

// Participant represent a view of other nodes for a node
type Participant struct {
	// The other node's ID
	id kyber.Scalar
	// This node's share of the other node's secret (derived from the first secret polynomial)
	secretShare1 kyber.Scalar
	// This node's share of the other node's secret (derived from the second secret polynomial)
	secretShare2 kyber.Scalar
	// The other node's public verification points, which are vectors derived
	// from the first and second secret polynomials.
	verificationPoints PointTuple
}

// Searches a node for its view of another node, given the other node's ID.
func (n *node) getParticipantByID(id kyber.Scalar) (p *Participant, _ error) {
	for _, participant := range n.otherParticipants {
		if participant.id == id {
			matchingParticipant := Participant{
				participant.id,
				participant.secretShare1,
				participant.secretShare2,
				participant.verificationPoints,
			}
			return &matchingParticipant, nil
		}
	}
	return nil, ParticipantNotFoundError{n.id, id}
}

// Compares two PointTuples, returning true if all vectors of each tuple are equal
func comparePointTuples(a, b PointTuple) bool {
	for i, pointA := range a {
		pointB := b[i]
		// fmt.Println("pointA: ", pointA)
		// fmt.Println("pointB: ", pointB)
		if !pointA.Equal(pointB) {
			return false
		}
	}
	return true
}

// Verifies that the secret shares a node has received from another node matches the other node's
// verification points
func (n *node) ProcessSecretShareVerification(id kyber.Scalar) (bool, error) {
	// alice's address
	ownAddress := n.id

	// bob's node
	p, err := n.getParticipantByID(id)
	if p == nil || err != nil {
		return false, err
	}

	// bob's shares
	share1 := p.secretShare1
	share2 := p.secretShare2

	// verify left hand side
	a := n.ScalarBaseMult(share1)
	b := n.curve.Point().Mul(share2, n.g2)
	vpoint := n.curve.Point().Add(a, b)
	vlhs := PointTuple{vpoint}

	// bob's verification points
	vrhs := make(PointTuple, len(n.secretPoly1))

	// verify right hand side
	pow := n.curve.Scalar().One()
	for i, point := range p.verificationPoints {
		p := n.curve.Point().Mul(pow, point)
		if i == 0 {
			vrhs[0] = p
		} else {
			vrhs[0] = n.curve.Point().Add(vrhs[0], p)
		}

		pow.Mul(pow, ownAddress)
	}

	if comparePointTuples(vlhs, vrhs) {
		return true, nil
	}
	// else fire complaint message
	// participant.get_or_create_complaint_by_complainer_address(ownAddress)
	return false, nil
}

// Evaluates a polynomial with argument x giving a result modulo n
func (poly ScalarPolynomial) evaluate(x kyber.Scalar) kyber.Scalar {
	res := x.Clone().Zero()
	xpow := x.Clone().One()
	for _, coeff := range poly {
		term := xpow.Clone()
		term.Mul(term, coeff)
		res.Add(res, term)
		xpow.Mul(xpow, x)
	}

	return res
}

// EvaluatePolynomials evaluates a node's secret polynomials given another node's ID, returning
// the node's secret shares for the other node.
func (n *node) EvaluatePolynomials(id kyber.Scalar) (kyber.Scalar, kyber.Scalar) {
	return n.secretPoly1.evaluate(id), n.secretPoly2.evaluate(id)
}

// generateSecretPolynomial creates a random scalar polynomial of degree threshold
func generateSecretPolynomial(curve kyber.Group, rand cipher.Stream, threshold int) (ScalarPolynomial, error) {
	secretPoly := make(ScalarPolynomial, threshold)

	for i := 0; i < threshold; i++ {
		// retrieve random scalar in-between 0 and base point order
		secretPoly[i] = curve.Scalar().Pick(rand)
	}

	err := secretPoly.validate(curve)
	if err != nil {
		return nil, err[0]
	}

	return secretPoly, nil
}

// GenerateNode generates a new DKG node randomly.
func GenerateNode(
	curve kyber.Group,
	g2 kyber.Point,
	zkParam kyber.Scalar,
	timeout time.Duration,
	id kyber.Scalar,
	rand cipher.Stream,
	threshold int,
) (*node, error) {
	secretPoly1, err := generateSecretPolynomial(curve, rand, threshold)
	if secretPoly1 == nil || err != nil {
		return nil, err
	}

	secretPoly2, err := generateSecretPolynomial(curve, rand, threshold)
	if secretPoly2 == nil || err != nil {
		return nil, err
	}

	generatedNode, err := NewNode(
		curve, g2, zkParam, timeout,
		id, secretPoly1, secretPoly2,
	)
	if generatedNode == nil || err != nil {
		return nil, err
	}

	return generatedNode, nil
}

// LagrangeInterpolateZero - find a constant in a source polynomial S=f(0) using Lagrange polynomials
// using computationally efficient approach https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing#Computationally_Efficient_Approach
func LagrangeInterpolateZero(points []struct{ x, fX kyber.Scalar }) kyber.Scalar {

	group := points[0].x // get group methods
	// zero := group.SetInt64(0)

	constant := group.SetInt64(0)
	for j := 0; j < len(points); j++ {
		// outer summation
		pointJ := points[j]

		product := group.SetInt64(1)

		for _, point := range points {
			if point.x == pointJ.x {
				continue
			}
			// inner products
			division := group.Div(point.x, group.Sub(point.x, pointJ.x)) // x_m / (x_m - x_j)
			product = group.Mul(product, division)                       // mathematical product

		}

		product = group.Mul(product, pointJ.fX) // final multiplication by f(x_j)
		constant = group.Add(constant, product)

	}
	return constant
}
