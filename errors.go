package dkg

import (
	"fmt"

	"github.com/dedis/kyber"
)

// InvalidCurveScalarError indicates a scalar is not a normalized field element for a given vector space
type InvalidCurveScalarError struct {
	curve kyber.Group
	k     kyber.Scalar
}

func (e InvalidCurveScalarError) Error() string {
	return fmt.Sprintf("dkg: invalid %v scalar %v",
		e.curve, e.k)
}

// InvalidCurveScalarPolynomialError indicates that a ScalarPolynomial is not constructed properly
type InvalidCurveScalarPolynomialError struct {
	curve     kyber.Group
	poly      ScalarPolynomial
	subErrors []error
}

func (e InvalidCurveScalarPolynomialError) Error() string {
	return fmt.Sprintf("dkg: invalid %v scalar polynomial %v (%v)",
		e.curve, e.poly, e.subErrors)
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
	curve kyber.Group
	g2    kyber.Point
}

func (e InvalidCurvePointError) Error() string {
	return fmt.Sprintf("dkg: invalid %v point %v",
		e.curve,
		e.g2,
	)
}

// ParticipantNotFoundError indicates a node with a particular ID could not be found in a node's participant list
type ParticipantNotFoundError struct {
	nodeID, participantID kyber.Scalar
}

func (e ParticipantNotFoundError) Error() string {
	return fmt.Sprintf("verification: participant: %v not in node: %v nodelist",
		e.nodeID, e.participantID,
	)
}

// InvalidPointsLengthError indicates that the number of points given was below the required amount
type InvalidPointsLengthError struct {
	len int
}

func (e InvalidPointsLengthError) Error() string {
	return fmt.Sprintf("invalid length of: %v given for points array", e.len)
}

// InvalidPointValueError scalar point value should not be nil
type InvalidPointValueError struct {
	value kyber.Scalar
}

func (e InvalidPointValueError) Error() string {
	return fmt.Sprintf("scalar point values: %v should not be nil", e.value)
}
