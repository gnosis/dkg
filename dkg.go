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

// ScalarPolynomial - type to represent polynomials in DKG protocol
type ScalarPolynomial []*big.Int

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

type node struct {
	curve    elliptic.Curve
	hash     hash.Hash
	g2x, g2y *big.Int
	zkParam  *big.Int
	timeout  time.Duration

	id          *big.Int
	key         ecdsa.PrivateKey
	secretPoly1 ScalarPolynomial
	secretPoly2 ScalarPolynomial

	broadcast chan Message

	otherParticipants []struct {
		id                 *big.Int
		key                ecdsa.PublicKey
		secretShare1       *big.Int
		secretShare2       *big.Int
		verificationPoints PointTuple

		private chan Message
	}
}

func isNormalizedScalar(x, n *big.Int) bool {
	return x != nil && x.Sign() >= 0 && x.Cmp(n) < 0
}

// NewNode - function to construct and return new nodes in DKG protocol
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

func (n *node) PublicKeyPart() (x, y *big.Int) {
	return n.curve.ScalarBaseMult(n.secretPoly1[0].Bytes())
}

// PointTuple - type to represent (x, y) points
type PointTuple []struct{ X, Y *big.Int }

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

// Participant - struct to represent participants in nodes
type Participant struct {
	id                 *big.Int
	key                ecdsa.PublicKey
	secretShare1       *big.Int
	secretShare2       *big.Int
	verificationPoints PointTuple
	private            chan Message
}

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

func comparePointTuples(a, b PointTuple) bool {
	for i, pointA := range a {
		pointB := b[i]
		// fmt.Println("pointA: ", pointA)
		// fmt.Println("pointB: ", pointB)
		if pointA.X.Uint64() != pointB.X.Uint64() || pointA.Y.Uint64() != pointB.Y.Uint64() {
			return false
		}
	}
	return true
}

// Verification step in dkg protocol
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

	// crypto base point order
	// var N = big.NewInt(int64(115792089237316195423570985008687907852837564279074904382605163141518161494337))

	// verify right hand side
	for i, point := range p.verificationPoints {
		var pow big.Int
		pow.Exp(ownAddress, big.NewInt(int64(i)), n.curve.Params().N)
		px, py := n.curve.ScalarMult(point.X, point.Y, pow.Bytes())
		if i == 0 {
			vrhs[0].X, vrhs[0].Y = px, py
		} else {
			vrhs[0].X, vrhs[0].Y = n.curve.Add(vrhs[0].X, vrhs[0].Y, px, py)
		}
	}

	if comparePointTuples(vlhs, vrhs) {
		return true, nil
	}
	// else fire complaint message
	// participant.get_or_create_complaint_by_complainer_address(ownAddress)
	return false, nil

}

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

var mask = []byte{0xff, 0x1, 0x3, 0x7, 0xf, 0x1f, 0x3f, 0x7f}

// GenerateNode - generates public key, private key, and secret polynomials, returns newNode()
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
