package dkg

import (
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/crypto/secp256k1"
)

// InvalidCurveScalarError - thrown when validation of ScalarPolynomial fails
type InvalidCurveScalarError struct {
	curve secp256k1.BitCurve
	k     *big.Int
}

func (e InvalidCurveScalarError) Error() string {
	return fmt.Sprintf("dkg: invalid %v scalar %64x",
		e.curve.Params().Name, e.k.Bytes())
}

// InvalidCurveScalarPolynomialError - thrown when construction of ScalarPolynomial fails
type InvalidCurveScalarPolynomialError struct {
	curve     secp256k1.BitCurve
	poly      ScalarPolynomial
	subErrors []error
}

func (e InvalidCurveScalarPolynomialError) Error() string {
	return fmt.Sprintf("dkg: invalid %v scalar polynomial %v (%v)",
		e.curve.Params().Name, e.poly, e.subErrors)
}

// InvalidScalarPolynomialLengthError - thrown when length of constructed ScalarPolnomials are unequal
type InvalidScalarPolynomialLengthError struct {
	poly1, poly2 ScalarPolynomial
}

func (e InvalidScalarPolynomialLengthError) Error() string {
	return fmt.Sprintf("dkg: scalar polynomial lengths don't match: %v != %v", len(e.poly1), len(e.poly2))
}

// InvalidCurvePointError - thrown when curve 2 points are not on base curve
type InvalidCurvePointError struct {
	curve    secp256k1.BitCurve
	g2x, g2y *big.Int
}

func (e InvalidCurvePointError) Error() string {
	return fmt.Sprintf("dkg: invalid %v point %x",
		e.curve.Params().Name,
		e.curve.Marshal(e.g2x, e.g2y),
	)
}

// ParticipantNotFoundError - thrown when participant not found in node's participant list
type ParticipantNotFoundError struct {
	nodeID, participantID *big.Int
}

func (e ParticipantNotFoundError) Error() string {
	return fmt.Sprintf("verification: participant: %v not in node: %v nodelist",
		e.nodeID, e.participantID,
	)
}
