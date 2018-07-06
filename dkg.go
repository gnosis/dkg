// Package dkg provides methods for distributed key generation.
package dkg

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"hash"
	"io"
	"log"
	"math/big"
	"time"
)

// ScalarPolynomial represents polynomials of scalars. It contains coefficients
// from the finite field under the vector space. Coefficient zero represents the constant
// term, coefficient one the linear term's coefficient, two the quadratic, etc.
type ScalarPolynomial []*big.Int

// validate ensures all elements of a scalar polynomial are compatible with a given
// finite field associated with the vector space given.
func (p ScalarPolynomial) validate(curve elliptic.Curve) []error {
	if len(p) <= 0 {
		return []error{errors.New("dkg: empty polynomial")}
	}

	var errors []error
	for _, c := range p {
		if c.Sign() == 0 || !isNormalizedScalar(c, curve.Params().N) {
			errors = append(errors, InvalidCurveScalarError{curve, c})
		}
	}
	return errors
}

// node represents a dkg node
type node struct {
	// The vector space underlying the protocol. Typically will be an elliptic curve.
	curve elliptic.Curve
	// The hash algorithm
	hash hash.Hash
	// A second element of the vector space for which the scalar k in the relation k * G = G2 is unknown.
	g2x, g2y *big.Int
	// A zero knowledge parameter agreed upon within the DKG group for proving possession of secrets
	// that have a corresponding vector
	zkParam *big.Int
	// A timeout for communications in the protocol
	timeout time.Duration

	// The ID associated with a node. Must be a scalar from the finite field underlying the vector space
	id  *big.Int
	key ecdsa.PrivateKey
	// The first secret polynomial for the node
	secretPoly1 ScalarPolynomial
	// The second secret polynomial for the node
	secretPoly2 ScalarPolynomial

	broadcast chan Message

	// This node's view of other nodes in the protocol
	otherParticipants []struct {
		id                 *big.Int
		key                ecdsa.PublicKey
		secretShare1       *big.Int
		secretShare2       *big.Int
		verificationPoints PointTuple

		private chan Message
	}
}

// isNormalizedScalar checks to see that 0 <= x < n.
func isNormalizedScalar(x, n *big.Int) bool {
	return x != nil && x.Sign() >= 0 && x.Cmp(n) < 0
}

// NewNode constructs a new node for DKG given some configuration variables.
func NewNode(
	curve elliptic.Curve,
	hash hash.Hash,
	g2x *big.Int, g2y *big.Int,
	zkParam *big.Int,
	timeout time.Duration,

	id *big.Int,
	key ecdsa.PrivateKey,
	secretPoly1 ScalarPolynomial,
	secretPoly2 ScalarPolynomial,
) (*node, error) {

	if !isNormalizedScalar(g2x, curve.Params().P) ||
		!isNormalizedScalar(g2y, curve.Params().P) ||
		!curve.IsOnCurve(g2x, g2y) {
		return nil, InvalidCurvePointError{curve, g2x, g2y}
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
		curve, hash, g2x, g2y, zkParam, timeout,
		id, key, secretPoly1, secretPoly2,
		nil, nil,
	}, nil
}

// PublicKeyPart retrieves the vector related to the constant term of a node's first secret polynomial.
func (n *node) PublicKeyPart() (x, y *big.Int) {
	return n.curve.ScalarBaseMult(n.secretPoly1[0].Bytes())
}

// PointTuple represents a set of vectors.
type PointTuple []struct{ X, Y *big.Int }

// VerificationPoints retrives a set of vectors which may be used to verify that secret shares
// sent to a node are legitimate.
func (n *node) VerificationPoints() PointTuple {
	// [c1 * G + c2 * G2 for c1, c2 in zip(spoly1, spoly2)]
	vpts := make(PointTuple, len(n.secretPoly1))
	for i, c1 := range n.secretPoly1 {
		c2 := n.secretPoly2[i]
		ax, ay := n.curve.ScalarBaseMult(c1.Bytes())
		bx, by := n.curve.ScalarMult(n.g2x, n.g2y, c2.Bytes())
		vpts[i].X, vpts[i].Y = n.curve.Add(ax, ay, bx, by)
	}
	return vpts
}

// Participant represent a view of other nodes for a node
type Participant struct {
	// The other node's ID
	id  *big.Int
	key ecdsa.PublicKey
	// This node's share of the other node's secret (derived from the first secret polynomial)
	secretShare1 *big.Int
	// This node's share of the other node's secret (derived from the second secret polynomial)
	secretShare2 *big.Int
	// The other node's public verification points, which are vectors derived
	// from the first and second secret polynomials.
	verificationPoints PointTuple
	private            chan Message
}

// Searches a node for its view of another node, given the other node's ID.
func (n *node) getParticipantByID(id *big.Int) (p *Participant, _ error) {
	for _, participant := range n.otherParticipants {
		if participant.id == id {
			matchingParticipant := Participant{
				participant.id,
				participant.key,
				participant.secretShare1,
				participant.secretShare2,
				participant.verificationPoints,
				participant.private,
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
		if pointA.X.Uint64() != pointB.X.Uint64() || pointA.Y.Uint64() != pointB.Y.Uint64() {
			return false
		}
	}
	return true
}

// Verifies that the secret shares a node has received from another node matches the other node's
// verification points
func (n *node) ProcessSecretShareVerification(id *big.Int) (bool, error) {
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
	ax, ay := n.curve.ScalarBaseMult(share1.Bytes())
	bx, by := n.curve.ScalarMult(n.g2x, n.g2y, share2.Bytes())
	vxlhs, vylhs := n.curve.Add(ax, ay, bx, by)
	vlhs := PointTuple{{vxlhs, vylhs}}

	// bob's verification points
	vrhs := make(PointTuple, len(n.secretPoly1))

	// secp256k1 base point order
	// var N = big.NewInt(int64(115792089237316195423570985008687907852837564279074904382605163141518161494337))

	// vxrhs, vyrhs := big.NewInt(0), big.NewInt(0)
	vrhs[0].X, vrhs[0].Y = big.NewInt(0), big.NewInt(0)
	// verify right hand side
	for i, point := range p.verificationPoints {
		var pow big.Int
		pow.Exp(ownAddress, big.NewInt(int64(i)), n.curve.Params().N)
		px, py := n.curve.ScalarMult(point.X, point.Y, pow.Bytes())
		vrhs[0].X, vrhs[0].Y = n.curve.Add(vrhs[0].X, vrhs[0].Y, px, py)
	}

	if comparePointTuples(vlhs, vrhs) {
		return true, nil
	}
	// else fire complaint message
	// participant.get_or_create_complaint_by_complainer_address(ownAddress)
	return false, nil
}

// EvaluatePolynomials evaluates a node's secret polynomials given another node's ID, returning
// the node's secret shares for the other node.
func (n *node) EvaluatePolynomials(id *big.Int) (*big.Int, *big.Int) {
	secretPoly1 := n.secretPoly1
	secretPoly2 := n.secretPoly2

	var share1 big.Int
	for i, scalar := range secretPoly1 {
		var res big.Int
		res.Exp(id, big.NewInt(int64(i)), n.curve.Params().N)
		res.Mul(&res, scalar)
		share1.Add(&res, &share1)
	}
	share1.Mod(&share1, n.curve.Params().N)

	var share2 big.Int
	for i, scalar := range secretPoly2 {
		var res big.Int
		res.Exp(id, big.NewInt(int64(i)), n.curve.Params().N)
		res.Mul(&res, scalar)
		share2.Add(&res, &share2)
	}
	share2.Mod(&share2, n.curve.Params().N)

	return &share1, &share2
}

// GeneratePublicShares returns a node's verification points as derived from its secret polynomials.
func (n *node) GeneratePublicShares(poly1, poly2 ScalarPolynomial) PointTuple {
	if len(poly1) != len(poly2) {
		log.Fatal("polynomial lengths do not match")
	}

	var sharesx *big.Int
	var sharesy *big.Int
	for i, scalar := range poly1 {
		curve1x, curve1y := n.curve.ScalarBaseMult(big.NewInt(int64(i)).Bytes())
		curve2x, curve2y := n.curve.ScalarMult(n.g2x, n.g2y, scalar.Bytes())
		sharesx, sharesy = n.curve.Add(curve1x, curve1y, curve2x, curve2y)
	}

	return PointTuple{{sharesx, sharesy}}

}

// generateSecretPolynomial creates a random scalar polynomial of degree threshold
func generateSecretPolynomial(curve elliptic.Curve, randReader io.Reader, threshold int) (ScalarPolynomial, error) {
	N := curve.Params().N
	secretPoly := make(ScalarPolynomial, threshold)

	for i := 0; i < threshold; i++ {
		// retrieve random scalar in-between 0 and base point order
		scalar, err := rand.Int(randReader, N)
		if err != nil {
			return nil, err
		}
		secretPoly[i] = scalar
	}

	err := secretPoly.validate(curve)
	if err != nil {
		return nil, err[0]
	}

	return secretPoly, nil
}

// GenerateNode generates a new DKG node randomly.
func GenerateNode(
	curve elliptic.Curve,
	hash hash.Hash,
	g2x *big.Int,
	g2y *big.Int,
	zkParam *big.Int,
	timeout time.Duration,
	id *big.Int,
	randReader io.Reader,
	threshold int,
) (*node, error) {
	key, err := ecdsa.GenerateKey(curve, randReader)
	if key == nil || err != nil {
		return nil, err
	}

	secretPoly1, err := generateSecretPolynomial(curve, randReader, threshold)
	if secretPoly1 == nil || err != nil {
		return nil, err
	}

	secretPoly2, err := generateSecretPolynomial(curve, randReader, threshold)
	if secretPoly2 == nil || err != nil {
		return nil, err
	}

	generatedNode, err := NewNode(
		curve, hash, g2x, g2y, zkParam, timeout,
		id, *key, secretPoly1, secretPoly2,
	)
	if generatedNode == nil || err != nil {
		return nil, err
	}

	return generatedNode, nil
}
