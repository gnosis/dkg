package dkg

import (
	"bytes"
	"encoding/gob"
	"log"
	"math/big"
	"reflect"
	"testing"
)

func getValidSecretSharingParams(t *testing.T) (
	From *big.Int,
	To *big.Int,
	S1x *big.Int,
	S1y *big.Int,
	S2x *big.Int,
	S2y *big.Int,
) {
	From = big.NewInt(12345)
	To = big.NewInt(67890)

	var success bool
	if S1x, success = new(big.Int).SetString("0a5d23f079fed8f443d7fa87d70849f846f941c07d77b1e1df139e8f7ff61a70", 16); !success {
		t.Errorf("Could not initialize S1x")
	}
	if S1y, success = new(big.Int).SetString("608e4edf904f2e1d5f54ddc708afec01fd2287fc95555139e065cbad4d5ecdba", 16); !success {
		t.Errorf("Could not initialize S1y")
	}
	if S2x, success = new(big.Int).SetString("0a5d23f079fed8f443d7fa87d70849f846f941c07d77b1e1df139e8f7ff61a70", 16); !success {
		t.Errorf("Could not initialize S2x")
	}
	if S2y, success = new(big.Int).SetString("608e4edf904f2e1d5f54ddc708afec01fd2287fc95555139e065cbad4d5ecdba", 16); !success {
		t.Errorf("Could not initialize S2y")
	}
	return
}

func getValidComplaintMessageParams(t *testing.T) (
	Accusor *big.Int,
	Accused *big.Int,
) {
	Accusor = big.NewInt(12345)
	Accused = big.NewInt(67890)
	return
}

func getValidPublicPointsMessageParams(t *testing.T) (
	Player *big.Int,
	Points PointTuple,
) {
	Player = big.NewInt(12345)

	curve, hash, g2x, g2y, zkParam, timeout, id, key, secretPoly1, secretPoly2 := getValidNodeParamsForTesting(t)

	node, err := NewNode(
		curve, hash, g2x, g2y, zkParam, timeout,
		id, key, secretPoly1, secretPoly2,
	)
	if node == nil || err != nil {
		log.Fatal("node construction failed")
	}
	log.Printf("node construction successful")

	Points = node.VerificationPoints()
	return
}

func createNetworkBuffer(t *testing.T) bytes.Buffer {
	var network bytes.Buffer
	return network
}

func compareSecretSharingMessageEquality(
	m1 *SecretSharesMessage,
	m2 *SecretSharesMessage,
) bool {
	if m1.From != m2.From || m1.To != m2.To ||
		m1.S1x != m2.S1x || m1.S1y != m2.S1y ||
		m1.S2x != m2.S2x || m1.S2y != m2.S2y {
		return false
	}
	return true
}

func compareComplaintMessageEquality(
	m1 *ComplaintMessage,
	m2 *ComplaintMessage,
) bool {
	if m1.Accusor != m2.Accusor || m1.Accused != m2.Accused {
		return false
	}
	return true
}

func comparePublicPointsMessageEquality(
	m1 *PublicPointsMessage,
	m2 *PublicPointsMessage,
) bool {
	if m1.Player != m2.Player || !reflect.DeepEqual(m1.Points, m2.Points) {
		return false
	}

	return true
}

func TestEncodeDecodeSecretSharesMessage(t *testing.T) {
	network := createNetworkBuffer(t)
	From, To, S1x, S1y, S2x, S2y := getValidSecretSharingParams(t)
	message := SecretSharesMessage{
		From, To, S1x, S1y, S2x, S2y,
	}

	enc := gob.NewEncoder(&network)
	err := enc.Encode(&message)
	if err != nil {
		log.Fatal("encode error: ", err)
	} else {
		log.Println("encode success")
	}

	dec := gob.NewDecoder(&network)
	var decoded SecretSharesMessage
	errd := dec.Decode(&decoded)
	if errd != nil {
		log.Fatal("decode error: ", err)
	} else {
		log.Println("decode success")
	}

	if compareSecretSharingMessageEquality(&message, &decoded) {
		t.Errorf(
			"Could not decode message with \n"+
				"network: %v\n"+
				"message: %v\n"+
				"decoded: %v\n",
			network, message, decoded,
		)
	} else {
		log.Println("successfully decoded secret sharing message")
	}
}

func TestEncodeDecodeComplaintMessage(t *testing.T) {
	network := createNetworkBuffer(t)
	Accusor, Accused := getValidComplaintMessageParams(t)
	message := ComplaintMessage{
		Accusor, Accused,
	}

	enc := gob.NewEncoder(&network)
	err := enc.Encode(&message)
	if err != nil {
		log.Fatal("encode error: ", err)
	} else {
		log.Println("encode success")
	}

	dec := gob.NewDecoder(&network)
	var decoded ComplaintMessage
	errd := dec.Decode(&decoded)
	if errd != nil {
		log.Fatal("decode error: ", err)
	} else {
		log.Println("decode success")
	}

	if compareComplaintMessageEquality(&message, &decoded) {
		t.Errorf(
			"Could not decode message with \n"+
				"network: %v\n"+
				"message: %v\n"+
				"decoded: %v\n",
			network, message, decoded,
		)
	} else {
		log.Println("successfully decoded complaint message")
	}
}

func TestEncodeDecodePublicPointsMessage(t *testing.T) {
	network := createNetworkBuffer(t)
	Player, Points := getValidPublicPointsMessageParams(t)
	message := PublicPointsMessage{
		Player, Points,
	}

	enc := gob.NewEncoder(&network)
	err := enc.Encode(&message)
	if err != nil {
		log.Fatal("encode error:", err)
	} else {
		log.Println("encode success")
	}

	dec := gob.NewDecoder(&network)
	var decoded PublicPointsMessage
	errd := dec.Decode(&decoded)
	if errd != nil {
		log.Fatal("decode error ", err)
	} else {
		log.Println("decode success")
	}

	if comparePublicPointsMessageEquality(&message, &decoded) {
		t.Errorf(
			"Could not decode message with \n"+
				"network: %v\n"+
				"message: %v\n"+
				"decoded: %v\n",
			network, message, decoded,
		)
	} else {
		log.Println("successfully decoded public points message")
	}
}
