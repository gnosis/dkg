package dkg

import "fmt"
import "crypto/elliptic"
import "math/big"

// InvalidCurveScalarError indicates a scalar is not a normalized field element for a given vector space
type InvalidCurveScalarError struct {
	curve elliptic.Curve
	k     *big.Int
}

func (e InvalidCurveScalarError) Error() string {
	return fmt.Sprintf("dkg: invalid %v scalar %64x",
		e.curve.Params().Name, e.k.Bytes())
}

// InvalidCurveScalarPolynomialError indicates that a ScalarPolynomial is not constructed properly
type InvalidCurveScalarPolynomialError struct {
	curve     elliptic.Curve
	poly      ScalarPolynomial
	subErrors []error
}

func (e InvalidCurveScalarPolynomialError) Error() string {
	return fmt.Sprintf("dkg: invalid %v scalar polynomial %v (%v)",
		e.curve.Params().Name, e.poly, e.subErrors)
}

// InvalidScalarPolynomialLengthError indicates that ScalarPolynomials which should have a matching degree don't
type InvalidScalarPolynomialLengthError struct {
	poly1, poly2 ScalarPolynomial
}

func (e InvalidScalarPolynomialLengthError) Error() string {
	return fmt.Sprintf("dkg: scalar polynomial lengths don't match: %v != %v", len(e.poly1), len(e.poly2))
}

// InvalidCurvePointError indicates that a given vector does not belong to a vector space
type InvalidCurvePointError struct {
	curve    elliptic.Curve
	g2x, g2y *big.Int
}

func (e InvalidCurvePointError) Error() string {
	return fmt.Sprintf("dkg: invalid %v point %x",
		e.curve.Params().Name,
		elliptic.Marshal(e.curve, e.g2x, e.g2y),
	)
}

// ParticipantNotFoundError indicates a node with a particular ID could not be found in a node's participant list
type ParticipantNotFoundError struct {
	nodeID, participantID *big.Int
}

func (e ParticipantNotFoundError) Error() string {
	return fmt.Sprintf("verification: participant: %v not in node: %v nodelist",
		e.nodeID, e.participantID,
	)
}
