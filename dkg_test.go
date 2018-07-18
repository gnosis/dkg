package dkg

import (
	"bytes"
	"encoding/base64"
	"reflect"
	"testing"
	"time"

	"github.com/dedis/kyber"
	"github.com/dedis/kyber/pairing/bn256"
)

func getValidNodeParamsForTesting(t *testing.T) (
	curve kyber.Group,
	g2 kyber.Point,
	zkParam kyber.Scalar,
	timeout time.Duration,
	id kyber.Scalar,
	secretPoly1 ScalarPolynomial,
	secretPoly2 ScalarPolynomial,
) {
	curve = bn256.NewSuite().G1()
	g2 = curve.Point().Base()
	g2.Mul(curve.Scalar().SetInt64(42), g2)

	zkParam = curve.Scalar().SetBytes([]byte("arbitrary zk proof parameter"))
	timeout = time.Duration(100 * time.Millisecond)

	id = curve.Scalar().SetInt64(12345)

	secretPoly1 = ScalarPolynomial{
		curve.Scalar().SetInt64(1),
		curve.Scalar().SetInt64(2),
		curve.Scalar().SetInt64(3),
		curve.Scalar().SetInt64(4),
	}
	secretPoly2 = ScalarPolynomial{
		curve.Scalar().SetInt64(5),
		curve.Scalar().SetInt64(6),
		curve.Scalar().SetInt64(7),
		curve.Scalar().SetInt64(8),
	}
	return
}

func serializePoint(curve kyber.Group, pt kyber.Point) string {
	return pt.String()
}

func addParticipantToNodeList(
	n *node,
	id kyber.Scalar,
	secretShare1 kyber.Scalar,
	secretShare2 kyber.Scalar,
	verificationPoints PointTuple,
) *node {
	participant := Participant{
		id,
		secretShare1,
		secretShare2,
		verificationPoints,
	}
	n.otherParticipants = append(n.otherParticipants, participant)
	return n
}

func TestInvalidNodeConstruction(t *testing.T) {
	curve, g2, zkParam, timeout, id, secretPoly1, secretPoly2 := getValidNodeParamsForTesting(t)

	t.Run("Invalid g2", func(t *testing.T) {
		badPoints := []kyber.Point{
			// identity rep can't be generator
			curve.Point().Null(),
		}

		for _, bad := range badPoints {
			node, err := NewNode(
				curve, bad, zkParam, timeout,
				id, secretPoly1, secretPoly2,
			)
			if node != nil && err == nil {
				t.Errorf(
					"Able to create node with invalid g2:\n"+
						"curve: %v\n"+
						"id: %T\n"+
						"g2: %v\n"+
						"secretPoly1: %v\n"+
						"secretPoly2: %v\n",
					curve, id, bad, secretPoly1, secretPoly2,
				)
			} else if reflect.TypeOf(err) != reflect.TypeOf((*InvalidCurvePointError)(nil)).Elem() {
				t.Errorf(
					"Got unexpected error from construction with invalid g2:\n"+
						"curve: %v\n"+
						"id: %T\n"+
						"g2: %v\n"+
						"secretPoly1: %v\n"+
						"secretPoly2: %v\n"+
						"%v\n",
					curve, id, bad, secretPoly1, secretPoly2, err,
				)
			}
		}
	})

	t.Run("Invalid polynomials", func(t *testing.T) {
		badPolys := []struct {
			poly1, poly2 ScalarPolynomial
		}{
			// can't have empty polynomials
			{ScalarPolynomial{}, ScalarPolynomial{}},
			{secretPoly1, ScalarPolynomial{}},
			{ScalarPolynomial{}, secretPoly2},
			// can't have polynomials with different lengths
			{secretPoly1, ScalarPolynomial{
				curve.Scalar().SetInt64(1),
				curve.Scalar().SetInt64(2),
				curve.Scalar().SetInt64(3),
			}},
			{ScalarPolynomial{
				curve.Scalar().SetInt64(1),
				curve.Scalar().SetInt64(2),
				curve.Scalar().SetInt64(3),
				curve.Scalar().SetInt64(4),
				curve.Scalar().SetInt64(5),
			}, secretPoly2},
			// can't have zero or unnormalized coefficients: 0 < coeff < curve.Params().N
			// {secretPoly1, ScalarPolynomial{curve.Scalar().SetInt64(1), curve.Scalar().SetInt64(-2), curve.Scalar().SetInt64(3), curve.Scalar().SetInt64(4)}},
			// {secretPoly1, ScalarPolynomial{curve.Scalar().SetInt64(1), curve.Scalar().SetInt64(2), curve.Scalar().SetInt64(3), curve.Scalar().SetInt64(0)}},
			// {secretPoly1, ScalarPolynomial{curve.Scalar().SetInt64(1), curve.Scalar().SetInt64(2), curve.Scalar().SetInt64(3), curve.Params().N}},
		}

		for _, bad := range badPolys {
			node, err := NewNode(
				curve, g2, zkParam, timeout,
				id, bad.poly1, bad.poly2,
			)
			if node != nil && err == nil {
				t.Errorf(
					"Able to create node with invalid polynomials:\n"+
						"curve: %v\n"+
						"id: %T\n"+
						"g2: %v\n"+
						"secretPoly1: %v\n"+
						"secretPoly2: %v\n",
					curve, id, g2, bad.poly1, bad.poly2,
				)
			} /* else if reflect.TypeOf(err) != reflect.TypeOf((*InvalidCurveScalarPolynomialError)(nil)).Elem() {
				t.Errorf(
					"Got unexpected error from construction with invalid polynomials:\n"+
						"curve: %v\n"+
						"id: %T\n"+
						"g2: %v\n"+
						"secretPoly1: %v\n"+
						"secretPoly2: %v\n"+
						"%v\n",
					curve, id, g2, bad.poly1, bad.poly2, err,
				)
			}*/
		}
	})
}

func TestValidNode(t *testing.T) {
	curve, g2, zkParam, timeout, id, secretPoly1, secretPoly2 := getValidNodeParamsForTesting(t)

	node, err := NewNode(
		curve, g2, zkParam, timeout,
		id, secretPoly1, secretPoly2,
	)

	if node == nil || err != nil {
		t.Errorf(
			"Could not create new node with params:\n"+
				"curve: %v\n"+
				"g2: %v\n"+
				"zkParam: %v\n"+
				"id: %v\n"+
				"secretPoly1: %v\n"+
				"secretPoly2: %v\n"+
				"%v\n",
			curve, serializePoint(curve, g2), zkParam, id, secretPoly1, secretPoly2, err,
		)
	} else {
		t.Run("PublicKeyPart", func(t *testing.T) {
			pub := node.PublicKeyPart()
			pubkeypt := serializePoint(curve, pub)
			if pubkeypt != "bn256.G1:(0000000000000000000000000000000000000000000000000000000000000001, 8fb501e34aa387f9aa6fecb86184dc21ee5b88d120b5b59e185cac6c5e089665)" {
				t.Errorf("Got unexpected public key part %v", pubkeypt)
			}
		})

		t.Run("VerificationPoints", func(t *testing.T) {
			vpts := node.VerificationPoints()
			vptsbuf := new(bytes.Buffer)
			for _, vpt := range vpts {
				vpt.MarshalTo(vptsbuf)
			}
			vptsb64 := base64.StdEncoding.EncodeToString(vptsbuf.Bytes())
			if vptsb64 != "EspGeGA+gxXPJUn80r8mjLXO0HTKd/FhcU0zxOF2HpZXC63Dh01NOvG9/IVLXmKbVJo/MPWpS+3/v2/nijj0h4Tn1NJF2r+qObJmk2bmBwSd23pvx4H9eapf9m69gQxCDeXaVXXjh4AVt2YGMJtKBG4w3Nd70CrROICWHTOzIIVYL5EN2slNRt1Ay1ocjmItlqIeT48TMXYfZz0TdpwVXxM61Af1VPcDOr/6ad57ZjqExK3UOE5y6msmwe1/7x7xXkDuh0mFfGGMOgHbGzuKCVVDzLkEU7/o3d2QRS9Bi7Y2gARzd0Lnh3q4GjikWsPB3q9mrnQBvO2UECfUO6wHaA==" {
				t.Errorf("Got unexpected verification points %v", vptsb64)
			}
		})
	}
}

func TestProcessSecretShareVerification(t *testing.T) {
	curve, g2, zkParam, timeout, id, secretPoly1, secretPoly2 := getValidNodeParamsForTesting(t)

	node1, err := NewNode(
		curve, g2, zkParam, timeout,
		id, secretPoly1, secretPoly2,
	)

	if node1 == nil || err != nil {
		t.Errorf(
			"Could not create new node with params:\n"+
				"curve: %v\n"+
				"zkparam: %v\n"+
				"g2: %v\n"+
				"id: %v\n"+
				"secretPoly1: %v\n"+
				"secretPoly2: %v\n"+
				"%v\n",
			curve, zkParam, serializePoint(curve, g2), id, secretPoly1, secretPoly2, err,
		)
	} else {
		t.Run("Participant not in node list", func(t *testing.T) {
			fakeNodeID := curve.Scalar().SetInt64(99999)

			verified, err := node1.ProcessSecretShareVerification(fakeNodeID)
			if verified || err == nil {
				t.Errorf(
					"Verified an unverified participant with params:\n"+
						"node id: %v\n"+
						"participant id: %v\n"+
						"other participants list length: %v\n"+
						"err: %v\n",
					node1.id, fakeNodeID, len(node1.otherParticipants), err,
				)
			}
		})

		t.Run("Participant in node list with invalid shares", func(t *testing.T) {
			validNodeID := curve.Scalar().SetInt64(12345)

			// add participant to node list with invalid shares
			invalidShare1, invalidShare2 := curve.Scalar().SetInt64(9), curve.Scalar().SetInt64(9)
			invalidPoints := PointTuple{curve.Point().Base()}
			node2 := addParticipantToNodeList(
				node1, validNodeID, invalidShare1, invalidShare2, invalidPoints,
			)

			verified, err := node2.ProcessSecretShareVerification(id)
			if verified {
				t.Errorf(
					"Verified a participant with invalid shares:\n"+
						"node id: %v\n"+
						"participant id: %v\n"+
						"invalid share1: %v\n"+
						"invalid share2: %v\n"+
						"err: %v\n",
					node2.id, validNodeID, invalidShare1, invalidShare2, err,
				)
			}
		})

		t.Run("Participant in node list with valid points", func(t *testing.T) {
			validNodeID := curve.Scalar().SetInt64(12345)

			// add participant to node list with valid shares
			validShare1, validShare2 := node1.EvaluatePolynomials(validNodeID)
			validPoints := node1.VerificationPoints()
			node3 := addParticipantToNodeList(
				node1, validNodeID, validShare1, validShare2, validPoints,
			)

			verified, err := node3.ProcessSecretShareVerification(validNodeID)
			if !verified || err != nil {
				t.Errorf(
					"Unable to verify a participant with valid shares:\n"+
						"node id: %v\n"+
						"participant id: %v\n"+
						"valid share1: %v\n"+
						"valid share2: %v\n"+
						"err: %v\n",
					node3.id, validNodeID, validShare1, validShare2, err,
				)
			}
		})
	}
}

func TestEvaluatePolynomials(t *testing.T) {
	curve, g2, zkParam, timeout, id, secretPoly1, secretPoly2 := getValidNodeParamsForTesting(t)

	node, err := NewNode(
		curve, g2, zkParam, timeout,
		id, secretPoly1, secretPoly2,
	)

	// invalidID := curve.Scalar().SetInt64(9)

	if node == nil || err != nil {
		t.Errorf(
			"Could not create new node with params:\n"+
				"curve: %v\n"+
				"zkparam:%v\n"+
				"g2: %v\n"+
				"id: %v\n"+
				"secretPoly1: %v\n"+
				"secretPoly2: %v\n"+
				"%v\n",
			curve, zkParam, serializePoint(curve, g2), id, secretPoly1, secretPoly2, err,
		)
	} else {
		// t.Run("invalid ID returns incorrect shares", func(t *testing.T) {
		// 	invalidShare1, invalidShare2 := node.EvaluatePolynomials(invalidID)
		// 	if (invalidShare1 is incorrect...) {
		// 		t.Errorf(
		// 			"invalid id should have invalid shares:\n"
		// 				"nodeID: %v\n"+
		// 				"invalidID: %v\n"+
		// 				"invalid share1: %v\n"+
		// 				"invalid share2: %v\n",
		// 			node.id, invalidID, invalidShare1, invalidShare2,
		// 		)

		// 	}
		// })

		t.Run("node returns correct shares", func(t *testing.T) {
			validNodeID := curve.Scalar().SetInt64(12345)
			correctShare1, correctShare2 := curve.Scalar().SetInt64(7525921076266), curve.Scalar().SetInt64(15051994576250)
			share1, share2 := node.EvaluatePolynomials(validNodeID)
			if !share1.Equal(correctShare1) || !share2.Equal(correctShare2) {
				t.Errorf(
					"node %v should have correct shares:\n"+
						"correct share1: %v\n"+
						"correct share2: %v\n"+
						"but received:\n"+
						"incorrect share1: %v\n"+
						"incorrect share2: %v\n",
					node.id, correctShare1, correctShare2, share1, share2,
				)
			}
		})
	}
}

func TestGenerateNodeAndSecrets(t *testing.T) {
	curve, g2, zkParam, timeout, id, _, _ := getValidNodeParamsForTesting(t)
	threshold := 4

	gNode, err := GenerateNode(
		curve, g2, zkParam,
		timeout, id, bn256.NewSuite().RandomStream(), threshold,
	)
	if gNode == nil || err != nil {
		t.Errorf(
			"Could not create new node with params:\n"+
				"curve: %v\n"+
				"zkparam:%v\n"+
				"g2: %v\n"+
				"id: %v\n"+
				"%v\n",
			curve, zkParam, serializePoint(curve, g2), id, err,
		)
	}

	t.Run("Add participants and verify shares", func(t *testing.T) {
		validNodeID := curve.Scalar().SetInt64(12345)

		//add participant to node list with valid shares
		validShare1, validShare2 := gNode.EvaluatePolynomials(validNodeID)
		validPoints := gNode.VerificationPoints()
		gNode := addParticipantToNodeList(
			gNode, validNodeID, validShare1, validShare2, validPoints,
		)

		verified, err := gNode.ProcessSecretShareVerification(validNodeID)
		if !verified || err != nil {
			t.Errorf(
				"Unable to verify a participant with valid shares:\n"+
					"node id: %v\n"+
					"participant id: %v\n"+
					"valid share1: %v\n"+
					"valid share2: %v\n"+
					"err: %v\n",
				gNode.id, validNodeID, validShare1, validShare2, err,
			)
		}
	})

}

func TestLagrangeInterpolationZero(t *testing.T) {

	curve, _, _, _, _, _, _ := getValidNodeParamsForTesting(t)
	rand := bn256.NewSuite().RandomStream()

	t.Run("should not create polynomials of order less than 1", func(t *testing.T) {
		order := 0
		poly, err := generateSecretPolynomial(curve, rand, order)

		if err == nil {
			t.Errorf(
				"generated invalid polynomial of order %v: %v\n"+
					"err: %v\n",
				order, poly, err,
			)
		}
	})

	t.Run("interpolation with invalid points should fail", func(t *testing.T) {
		order := 2
		poly, err := generateSecretPolynomial(curve, rand, order)
		if err != nil {
			t.Errorf("Could not generate polynomial: %v", err)
			return
		}

		invalidSamplePoints := make([]struct {
			x  kyber.Scalar
			fX kyber.Scalar
		}, order)

		for i := range invalidSamplePoints {
			invalidSamplePoints[i].x = curve.Scalar().Pick(rand)
			invalidSamplePoints[i].fX = curve.Scalar().Pick(rand)
		}

		res, err := LagrangeInterpolateZero(invalidSamplePoints, curve)

		expected := poly[0]

		if !expected.Equal(poly.evaluate(curve.Scalar().Zero())) {
			t.Errorf("Polynomial zero should be same as constant coefficient")
			return
		}

		if expected.Equal(res) || err != nil {
			t.Errorf(
				"Polynomials should not match\n"+
					"expected: %v\n"+
					"actual: %v\n"+
					"polynomial coefficients %v\n"+
					"err: %v\n",
				expected, res, poly, err,
			)
		}
	})

	t.Run("calculates basic order 2 polynomial result", func(t *testing.T) {
		// 1. create a random polynomial with threshold t
		// 2. sample t points from it (x1, fX1) ... (xt, fXt) (this is using the evaluate function)
		// 3. pass those points into LagrangeInterpolateZero(..) and verify that the result of that == random polynomial `evaluate`d at 0
		order := 2
		poly, err := generateSecretPolynomial(curve, rand, order)
		if err != nil {
			t.Errorf("Could not generate polynomial: %v", err)
			return
		}

		samplePoints := make([]struct {
			x  kyber.Scalar
			fX kyber.Scalar
		}, order)
		for i := range samplePoints {
			samplePoints[i].x = curve.Scalar().Pick(rand)
			samplePoints[i].fX = poly.evaluate(samplePoints[i].x)
		}

		res, err := LagrangeInterpolateZero(samplePoints, curve)

		expected := poly[0]

		if !expected.Equal(poly.evaluate(curve.Scalar().Zero())) {
			t.Errorf("Polynomial zero should be same as constant coefficient")
			return
		}

		if !expected.Equal(res) || err != nil {
			t.Errorf(
				"Polynomials do not match\n"+
					"expected: %v\n"+
					"actual:   %v\n"+
					"polynomial coefficients: %v\n"+
					"err: %v\n",
				expected, res, poly, err,
			)
		}
	})

	t.Run("calculates higher order 10 polynomial result", func(t *testing.T) {
		order := 10
		poly, err := generateSecretPolynomial(curve, rand, order)
		if err != nil {
			t.Errorf("Could not generate polynomial: %v", err)
			return
		}

		samplePoints := make([]struct {
			x  kyber.Scalar
			fX kyber.Scalar
		}, order)
		for i := range samplePoints {
			samplePoints[i].x = curve.Scalar().Pick(rand)
			samplePoints[i].fX = poly.evaluate(samplePoints[i].x)
		}

		res, err := LagrangeInterpolateZero(samplePoints, curve)

		expected := poly[0]

		if !expected.Equal(poly.evaluate(curve.Scalar().Zero())) {
			t.Errorf("Polynomial zero should be same as constant coefficient")
			return
		}

		if !expected.Equal(res) || err != nil {
			t.Errorf(
				"Polynomials do not match\n"+
					"expected: %v\n"+
					"actual: %v\n"+
					"polynomial coefficients %v\n"+
					"err: %v\n",
				expected, res, poly, err,
			)
		}
	})
}
