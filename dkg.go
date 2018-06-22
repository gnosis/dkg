package dkg

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"errors"
	"hash"
	"log"
	"math/big"
	"time"
	// "github.com/ethereum/go-ethereum/crypto/secp256k1"
)

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
		verificationPoints pointTuple

		private chan Message
	}
}

func isNormalizedScalar(x, n *big.Int) bool {
	return x != nil && x.Sign() >= 0 && x.Cmp(n) < 0
}

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

	return &node{
		curve, hash, g2x, g2y, zkParam, timeout,
		id, key, secretPoly1, secretPoly2,
		nil, nil,
	}, nil
}

func (n *node) PublicKeyPart() (x, y *big.Int) {
	return n.curve.ScalarBaseMult(n.secretPoly1[0].Bytes())
}

type pointTuple []struct{ X, Y *big.Int }

func (n *node) VerificationPoints() pointTuple {
	// [c1 * G + c2 * G2 for c1, c2 in zip(spoly1, spoly2)]
	vpts := make(pointTuple, len(n.secretPoly1))
	for i, c1 := range n.secretPoly1 {
		c2 := n.secretPoly2[i]
		ax, ay := n.curve.ScalarBaseMult(c1.Bytes())
		bx, by := n.curve.ScalarMult(n.g2x, n.g2y, c2.Bytes())
		vpts[i].X, vpts[i].Y = n.curve.Add(ax, ay, bx, by)
	}
	return vpts
}

type participant struct {
	id                 *big.Int
	key                ecdsa.PublicKey
	secretShare1       *big.Int
	secretShare2       *big.Int
	verificationPoints pointTuple
	private            chan Message
}

func (n *node) getParticipantById(id *big.Int) (p *participant, _ error) {
	for _, participant := range n.otherParticipants {
		if participant.id == id {
			return
		}
	}
	return
}

func comparePointTuples(a, b pointTuple) bool {
	for i, pointA := range a {
		pointB := b[i]
		if pointA.X != pointB.X || pointA.Y != pointB.X {
			return false
		}
	}
	return true
}

// Verification step in dkg protocol
func (n *node) ProcessSecretShareVerification(id *big.Int) bool {
	// alice's address
	ownAddress := n.id

	// bob's node
	p, err := n.getParticipantById(id)
	if p == nil || err != nil {
		log.Fatal("participant not in node list")
	}

	// bob's shares
	share1 := p.secretShare1
	share2 := p.secretShare2

	// verify left hand side
	ax, ay := n.curve.ScalarBaseMult(share1.Bytes())
	bx, by := n.curve.ScalarMult(n.g2x, n.g2y, share2.Bytes())
	vxlhs, vylhs := n.curve.Add(ax, ay, bx, by)
	vlhs := pointTuple{{vxlhs, vylhs}}

	// bob's verification points
	var vxrhs *big.Int
	var vyrhs *big.Int

	// secp256k1 base point order
	// var N = big.NewInt(int64(115792089237316195423570985008687907852837564279074904382605163141518161494337))

	// verify right hand side
	for i, point := range p.verificationPoints {
		var pow *big.Int
		pow.Exp(ownAddress, big.NewInt(int64(i)), n.curve.Params().N)
		px, py := n.curve.ScalarMult(point.X, point.Y, pow.Bytes())
		vxrhs, vyrhs = n.curve.Add(vxrhs, vyrhs, px, py)
	}
	vrhs := pointTuple{{vxrhs, vyrhs}}

	if comparePointTuples(vlhs, vrhs) {
		return true
	}
	return false
	// else fire complaint message
	// participant.get_or_create_complaint_by_complainer_address(ownAddress)
}

func (n *node) EvaluatePolynomials(secretPoly1 ScalarPolynomial, secretPoly2 ScalarPolynomial, id *big.Int) (*big.Int, *big.Int) {
	var share1 *big.Int
	for i, scalar := range secretPoly1 {
		var res *big.Int
		res.Exp(id, big.NewInt(int64(i)), n.curve.Params().N)
		res.Mul(res, scalar)
		share1.Add(res, share1)
	}
	share1.Mod(share1, n.curve.Params().N)

	var share2 *big.Int
	for i, scalar := range secretPoly2 {
		var res *big.Int
		res.Exp(id, big.NewInt(int64(i)), n.curve.Params().N)
		res.Mul(res, scalar)
		share2.Add(res, share2)
	}
	share2.Mod(share2, n.curve.Params().N)
	return share1, share2
}
