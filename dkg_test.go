package dkg

import (
	"bytes"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"math/big"
	"reflect"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
)

// import "bytes"

func getValidNodeParamsForTesting(t *testing.T) (
	curve elliptic.Curve,
	g2x *big.Int,
	g2y *big.Int,
	zkParam *big.Int,
	timeout time.Duration,
	id *big.Int,
	secretPoly1 ScalarPolynomial,
	secretPoly2 ScalarPolynomial,
) {

	// curve = elliptic.P256()
	curve = crypto.S256()
	hash = sha512.New512_256()

	var success bool
	if g2x, success = new(big.Int).SetString("b25b5ea8b8b230e5574fec0182e809e3455701323968c602ab56b458d0ba96bf", 16); !success {
		t.Errorf("Could not initialize g2x")
	}
	if g2y, success = new(big.Int).SetString("13edfe75e1c88e030eda220ffc74802144aec67c4e51cb49699d4401c122e19c", 16); !success {
		t.Errorf("Could not initialize g2y")
	}

	zkParam = new(big.Int).SetBytes([]byte("arbitrary zk proof parameter"))
	timeout = time.Duration(100 * time.Millisecond)

	id = big.NewInt(12345)

	secretPoly1 = ScalarPolynomial{big.NewInt(1), big.NewInt(2), big.NewInt(3), big.NewInt(4)}
	secretPoly2 = ScalarPolynomial{big.NewInt(5), big.NewInt(6), big.NewInt(7), big.NewInt(8)}
	return
}

func serializePoint(curve elliptic.Curve, x, y *big.Int) string {
	return base64.StdEncoding.EncodeToString(elliptic.Marshal(curve, x, y))
}

func addParticipantToNodeList(
	n *node,
	id *big.Int,
	secretShare1 *big.Int,
	secretShare2 *big.Int,
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
	curve, g2x, g2y, zkParam, timeout, id, secretPoly1, secretPoly2 := getValidNodeParamsForTesting(t)
	zero := big.NewInt(0)

	t.Run("Invalid g2", func(t *testing.T) {
		badPoints := []struct {
			x, y *big.Int
		}{
			// identity rep can't be generator
			{zero, zero},
			// shouldn't allow unnormalized representations
			{g2x, new(big.Int).Add(new(big.Int).Neg(curve.Params().P), g2y)},
			{g2x, new(big.Int).Add(curve.Params().P, g2y)},
			// shouldn't allow non-curve points
			{big.NewInt(1), big.NewInt(1)},
			{big.NewInt(31546753643215432), big.NewInt(2345436543254564)},
		}

		for _, bad := range badPoints {
			node, err := NewNode(
				curve, bad.x, bad.y, zkParam, timeout,
				id, secretPoly1, secretPoly2,
			)
			if node != nil && err == nil {
				t.Errorf(
					"Able to create node with invalid g2:\n"+
						"curve: %v\n"+
						"id: %T\n"+
						"g2: %v, %v\n"+
						"secretPoly1: %v\n"+
						"secretPoly2: %v\n",
					curve.Params().Name, id, bad.x, bad.y, secretPoly1, secretPoly2,
				)
			} else if reflect.TypeOf(err) != reflect.TypeOf((*InvalidCurvePointError)(nil)).Elem() {
				t.Errorf(
					"Got unexpected error from construction with invalid g2:\n"+
						"curve: %v\n"+
						"id: %T\n"+
						"g2: %x %x\n"+
						"secretPoly1: %v\n"+
						"secretPoly2: %v\n"+
						"%v\n",
					curve.Params().Name, id, bad.x, bad.y, secretPoly1, secretPoly2, err,
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
			{secretPoly1, ScalarPolynomial{big.NewInt(1), big.NewInt(2), big.NewInt(3)}},
			{ScalarPolynomial{big.NewInt(1), big.NewInt(2), big.NewInt(3), big.NewInt(4), big.NewInt(5)}, secretPoly2},
			// can't have zero or unnormalized coefficients: 0 < coeff < curve.Params().N
			{secretPoly1, ScalarPolynomial{big.NewInt(1), big.NewInt(-2), big.NewInt(3), big.NewInt(4)}},
			{secretPoly1, ScalarPolynomial{big.NewInt(1), big.NewInt(2), big.NewInt(3), big.NewInt(0)}},
			{secretPoly1, ScalarPolynomial{big.NewInt(1), big.NewInt(2), big.NewInt(3), curve.Params().N}},
		}

		for _, bad := range badPolys {
			node, err := NewNode(
				curve, g2x, g2y, zkParam, timeout,
				id, bad.poly1, bad.poly2,
			)
			if node != nil && err == nil {
				t.Errorf(
					"Able to create node with invalid polynomials:\n"+
						"curve: %v\n"+
						"id: %T\n"+
						"g2: %v, %v\n"+
						"secretPoly1: %v\n"+
						"secretPoly2: %v\n",
					curve.Params().Name, id, g2x, g2y, bad.poly1, bad.poly2,
				)
			} else if reflect.TypeOf(err) != reflect.TypeOf((*InvalidCurveScalarPolynomialError)(nil)).Elem() {
				t.Errorf(
					"Got unexpected error from construction with invalid polynomials:\n"+
						"curve: %v\n"+
						"id: %T\n"+
						"g2: %x %x\n"+
						"secretPoly1: %v\n"+
						"secretPoly2: %v\n"+
						"%v\n",
					curve.Params().Name, id, g2x, g2y, bad.poly1, bad.poly2, err,
				)
			}
		}
	})
}

func TestValidNode(t *testing.T) {
	curve, g2x, g2y, zkParam, timeout, id, secretPoly1, secretPoly2 := getValidNodeParamsForTesting(t)

	node, err := NewNode(
		curve, g2x, g2y, zkParam, timeout,
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
			curve.Params().Name, zkParam, serializePoint(curve, g2x, g2y), id, secretPoly1, secretPoly2, err,
		)
	} else {
		t.Run("PublicKeyPart", func(t *testing.T) {
			pubx, puby := node.PublicKeyPart()
			pubkeypt := serializePoint(curve, pubx, puby)
			if pubkeypt != "BHm+Zn753LusVaBilc6HCwcCm/zbLc4o2VnygVsW+BeYSDradyajxGVdpPv8DhEIqP0XtEimhVQZnEfQj/sQ1Lg=" {
				t.Errorf("Got unexpected public key part %v", pubkeypt)
			}
		})

		t.Run("VerificationPoints", func(t *testing.T) {
			vpts := node.VerificationPoints()
			vptsbuf := new(bytes.Buffer)
			for _, vpt := range vpts {
				vptsbuf.Write(elliptic.Marshal(node.curve, vpt.X, vpt.Y))
			}
			vptsb64 := base64.StdEncoding.EncodeToString(vptsbuf.Bytes())
			if vptsb64 != "BMax5xZSzXQf/krKIPf8Um8VxtNkXF900ov5zLIRjlFMrSY43/vaRKlWBdFNX2wW1rRHeRCMiDEQWKbI7fZQDowEbSctUYDuj/77Gwf8m8v8JOvB7Tw8lo6dBF9AYTV8CgMbJo9Srf0xwDGJtwreJFx3ponCK3ivyS8uNQ3O6u5dBgQabgTZtjLYdlgunq9MAao8wgJfq2cxjVXEPVClj7oXFpUJkWuXDS5YvzVlXQHXWS2o0MW/KgMLfatVkOFI+WbGBH4yrdF3UYCk1C/+BQctVteaD+wLLaXZ95Ygr/kgPIFYRFCE30uMAXnGYIvjofbpSJ8fwnDFj2zizRTVBvixcVg=" {
				t.Errorf("Got unexpected verification points %v", vptsb64)
			}
		})
	}
}

func TestProcessSecretShareVerification(t *testing.T) {
	curve, g2x, g2y, zkParam, timeout, id, secretPoly1, secretPoly2 := getValidNodeParamsForTesting(t)

	node1, err := NewNode(
		curve, g2x, g2y, zkParam, timeout,
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
			curve.Params().Name, zkParam, serializePoint(curve, g2x, g2y), id, secretPoly1, secretPoly2, err,
		)
	} else {
		t.Run("Participant not in node list", func(t *testing.T) {
			fakeNodeID := big.NewInt(99999)

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
			validNodeID := big.NewInt(12345)

			// add participant to node list with invalid shares
			invalidShare1, invalidShare2 := big.NewInt(9), big.NewInt(9)
			invalidPoints := PointTuple{{big.NewInt(9), big.NewInt(9)}}
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
			validNodeID := big.NewInt(12345)

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
	curve, g2x, g2y, zkParam, timeout, id, secretPoly1, secretPoly2 := getValidNodeParamsForTesting(t)

	node, err := NewNode(
		curve, g2x, g2y, zkParam, timeout,
		id, secretPoly1, secretPoly2,
	)

	// invalidID := big.NewInt(9)

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
			curve.Params().Name, zkParam, serializePoint(curve, g2x, g2y), id, secretPoly1, secretPoly2, err,
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
			validNodeID := big.NewInt(12345)
			correctShare1, correctShare2 := big.NewInt(7525921076266), big.NewInt(15051994576250)
			share1, share2 := node.EvaluatePolynomials(validNodeID)
			if share1.Uint64() != correctShare1.Uint64() || share2.Uint64() != correctShare2.Uint64() {
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
	curve, g2x, g2y, zkParam, timeout, id, _, _ := getValidNodeParamsForTesting(t)
	threshold := 4

	gNode, err := GenerateNode(
		curve, g2x, g2y, zkParam,
		timeout, id, rand.Reader, threshold,
	)
	if gNode == nil || err != nil {
		t.Errorf(
			"Could not create new node with params:\n"+
				"curve: %v\n"+
				"zkparam:%v\n"+
				"g2: %v\n"+
				"id: %v\n"+
				"%v\n",
			curve.Params().Name, zkParam, serializePoint(curve, g2x, g2y), id, err,
		)
	}

	t.Run("Add participants and verify shares", func(t *testing.T) {
		validNodeID := big.NewInt(12345)

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
