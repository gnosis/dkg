package dkg

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha512"
	"encoding/base64"
	"hash"
	"math/big"
	"reflect"
	"testing"
	"time"
)

// import "bytes"

func getValidNodeParamsForTesting(t *testing.T) (
	curve elliptic.Curve,
	hash hash.Hash,
	g2x *big.Int,
	g2y *big.Int,
	zkParam *big.Int,
	timeout time.Duration,
	id *big.Int,
	key ecdsa.PrivateKey,
	secretPoly1 ScalarPolynomial,
	secretPoly2 ScalarPolynomial,
) {
	curve = elliptic.P256()
	hash = sha512.New512_256()

	var success bool
	if g2x, success = new(big.Int).SetString("0a5d23f079fed8f443d7fa87d70849f846f941c07d77b1e1df139e8f7ff61a70", 16); !success {
		t.Errorf("Could not initialize g2x")
	}
	if g2y, success = new(big.Int).SetString("608e4edf904f2e1d5f54ddc708afec01fd2287fc95555139e065cbad4d5ecdba", 16); !success {
		t.Errorf("Could not initialize g2y")
	}

	zkParam = new(big.Int).SetBytes([]byte("arbitrary zk proof parameter"))
	timeout = time.Duration(100 * time.Millisecond)

	id = big.NewInt(12345)

	privd := big.NewInt(1234567890)
	pubx, puby := curve.ScalarBaseMult(privd.Bytes())

	key = ecdsa.PrivateKey{
		ecdsa.PublicKey{curve, pubx, puby},
		privd,
	}
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
	key ecdsa.PublicKey,
	secretShare1 *big.Int,
	secretShare2 *big.Int,
	verificationPoints PointTuple,
	private chan Message,
) *node {
	participant := Participant{
		id,
		key,
		secretShare1,
		secretShare2,
		verificationPoints,
		private}
	n.otherParticipants = append(n.otherParticipants, participant)
	return n
}

func TestInvalidNodeConstruction(t *testing.T) {
	curve, hash, g2x, g2y, zkParam, timeout, id, key, secretPoly1, secretPoly2 := getValidNodeParamsForTesting(t)
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
				curve, hash, bad.x, bad.y, zkParam, timeout,
				id, key, secretPoly1, secretPoly2,
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
				curve, hash, g2x, g2y, zkParam, timeout,
				id, key, bad.poly1, bad.poly2,
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
	curve, hash, g2x, g2y, zkParam, timeout, id, key, secretPoly1, secretPoly2 := getValidNodeParamsForTesting(t)

	node, err := NewNode(
		curve, hash, g2x, g2y, zkParam, timeout,
		id, key, secretPoly1, secretPoly2,
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
			if pubkeypt != "BGsX0fLhLEJH+Lzm5WOkQPJ3A32BLeszoPShOUXYmMKWT+NC4v4af5uO5+tKfA+eFivOM1drMV7Oy7ZAaDe/UfU=" {
				t.Errorf("Got unexpected public key part %v", pubkeypt)
			}
		})

		t.Run("VerificationPoints", func(t *testing.T) {
			vpts := node.VerificationPoints()
			vptsbuf := new(bytes.Buffer)
			for _, vpt := range vpts {
				vptsbuf.Write(elliptic.Marshal(curve, vpt.X, vpt.Y))
			}
			vptsb64 := base64.StdEncoding.EncodeToString(vptsbuf.Bytes())
			if vptsb64 != "BBRPCyOypp95ucbYOZTBcfoFklBEE2Hi3aFplbHeTmth17kAicWtDqV1IW/pqP0lEvv7ryW6ChH1Tw3V9I6WZOwEUyCd5oet8nQmjgHXn7uDW4wrnH23de/fVm9aO6Te4CfrhI3o0b0KFY/E7Z+gEGtLhE3zNFOwhEM5nQC/NNr4hQSgtaBOX63vRhZF3vZS5PdwaH2gDHY2cEBz2iETYHeliziLq1WGn10XqAmdT4vOtvYuFlxWUiHpJFILbi4LpMwNBFW0kj8eA8IieBQBqaU/eHALCS1QvAVW8zOriM+ZnlhxDkE6sX8aDPoQsCZ8EjAKt9N52qKsf8+YF8tSG403rxM=" {
				t.Errorf("Got unexpected verification points %v", vptsb64)
			}
		})
	}
}

func TestProcessSecretShareVerification(t *testing.T) {
	curve, hash, g2x, g2y, zkParam, timeout, id, key, secretPoly1, secretPoly2 := getValidNodeParamsForTesting(t)

	node1, err := NewNode(
		curve, hash, g2x, g2y, zkParam, timeout,
		id, key, secretPoly1, secretPoly2,
	)

	if node1 == nil || err != nil {
		t.Errorf(
			"Could not create new node with params:\n"+
				"curve: %v\n"+
				"g2: %v\n"+
				"zkparam: %v\n"+
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
						"other participants list length: %v\n",
					node1.id, fakeNodeID, len(node1.otherParticipants),
				)
			}
		})

		t.Run("Participant in node list with invalid shares", func(t *testing.T) {
			validPubKey := ecdsa.PublicKey{key.Curve, key.X, key.Y}
			validNodeID := big.NewInt(54321)

			// add participant to node list with invalid shares
			invalidShare1, invalidShare2 := big.NewInt(9), big.NewInt(9)
			invalidPoints := PointTuple{{big.NewInt(9), big.NewInt(9)}}
			node2 := addParticipantToNodeList(
				node1, validNodeID, validPubKey, invalidShare1, invalidShare2, invalidPoints, node1.broadcast,
			)

			verified, _ := node2.ProcessSecretShareVerification(id)
			if verified {
				t.Errorf(
					"Verified a participant with invalid shares:\n"+
						"node id: %v\n"+
						"participant id: %v\n"+
						"invalid share1: %v\n"+
						"invalid share2: %v\n",
					node2.id, validNodeID, invalidShare1, invalidShare2,
				)
			}
		})

		t.Run("Participant in node list with valid points", func(t *testing.T) {
			validPubKey := ecdsa.PublicKey{key.Curve, key.X, key.Y}
			validNodeID := big.NewInt(11111)

			// add participant to node list with valid shares
			validShare1, validShare2 := node1.EvaluatePolynomials()
			validPoints := node1.VerificationPoints()
			node3 := addParticipantToNodeList(
				node1, validNodeID, validPubKey, validShare1, validShare2, validPoints, node1.broadcast,
			)

			verified, _ := node3.ProcessSecretShareVerification(validNodeID)
			if !verified {
				t.Errorf(
					"Unable to verify a participant with valid shares:\n"+
						"node id: %v\n"+
						"participant id: %v\n"+
						"valid share1: %v\n"+
						"valid share2: %v\n",
					node3.id, validNodeID, validShare1, validShare2,
				)
			}
		})

	}
}

func TestEvaluatePolynomials(t *testing.T) {
	curve, hash, g2x, g2y, zkParam, timeout, id, key, secretPoly1, secretPoly2 := getValidNodeParamsForTesting(t)

	node, err := NewNode(
		curve, hash, g2x, g2y, zkParam, timeout,
		id, key, secretPoly1, secretPoly2,
	)

	// validID := big.NewInt(1)

	// invalidID := big.NewInt(9)

	if node == nil || err != nil {
		t.Errorf(
			"Could not create new node with params:\n"+
				"curve: %v\n"+
				"g2: %v\n"+
				"zkparam:%v\n"+
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

		// t.Run("Valid ID returns valid shares", func(t *testing.T) {
		// 	validShare1, validShare2 := node.EvaluatePolynomials(validID)
		// 	if (validShares are invalid...) {
		// 		t.Errorf(
		// 			"valid id should have valid shares:\n"+
		// 				"nodeID: %v\n"+
		// 				"validID: %v\n"+
		// 				"valid share1: %v\n"+
		// 				"valid share2: %v\n",
		// 			node.id, validID, validShare1, validShare2,
		// 		)
		// 	}
		// })
	}

}
