package dkg

import "errors"
import "hash"
import "time"
import "crypto/ecdsa"
import "crypto/elliptic"
import "math/big"
import "reflect"
import "log"

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

func (n *node) getParticipantByAddress(address *big.Int) (p participant, _ error) {
	for _, participant := range n.otherParticipants {
		if participant.id == address {
			return
		}
	}
	return
}

func (n *node) ProcessSecretShareVerification(address *big.Int) {
	// // alice's address
	// ownAddress := n.id

	// bob's address
	p, err := n.getParticipantByAddress(address)
	if err != nil {
		log.Fatal("participant not in node list")
	}

	// // bob's shares
	// share1 := p.secretShare1
	// share2 := p.secretShare2

	// bob's vpts
	// bvpts (secp256k1.G * share1) + (G2, share2)
	bvpts := p.verificationPoints

	// Alice's vpts
	// avpts = functools.reduce()
	avpts := n.VerificationPoints()

	if reflect.DeepEqual(bvpts, avpts) {
		return
	}
	// else fire complaint message
	// participant.get_or_create_complaint_by_complainer_address(ownAddress)
}
