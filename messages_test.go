package dkg

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"log"
	"math/big"
	"testing"
)

func getValidMessageParamsForTesting(t *testing.T) (
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

func createNetworkBuffer(t *testing.T) bytes.Buffer {
	var network bytes.Buffer
	return network
}

func compareMessageEquality(
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

func TestCreateValidMessage(t *testing.T) {
	From, To, S1x, S1y, S2x, S2y := getValidMessageParamsForTesting(t)

	message := NewSecretSharesMessage(
		From, To, S1x, S1y, S2x, S2y,
	)

	if message == nil {
		t.Errorf(
			"Could not create message with params \n"+
				"From: %v\n"+
				"To: %v\n"+
				"S1x: %v\n"+
				"S1y: %v\n"+
				"S2x: %v\n"+
				"S2y: %v\n",
			From, To, S1x, S1y, S2x, S2y,
		)
	} else {
		fmt.Println("creates valid messages")
	}
}

func TestEncodeDecodeValidMessage(t *testing.T) {
	network := createNetworkBuffer(t)
	From, To, S1x, S1y, S2x, S2y := getValidMessageParamsForTesting(t)
	message := NewSecretSharesMessage(
		From, To, S1x, S1y, S2x, S2y,
	)

	enc := gob.NewEncoder(&network)
	err := enc.Encode(message)
	if err != nil {
		log.Fatal("encode error:", err)
	} else {
		log.Println("encode success")
	}

	dec := gob.NewDecoder(&network)
	var decoded SecretSharesMessage
	errd := dec.Decode(&decoded)
	if errd != nil {
		log.Fatal("decode error ", err)
	} else {
		log.Println("decode success")
	}

	encodedRes := EncodeSecretSharesMessage(&network, message)
	if !encodedRes {
		t.Errorf(
			"Could not encode message with \n"+
				"network: %v\n"+
				"message: %v\n",
			network, message,
		)
	} else {
		fmt.Println("successfully encoded message")
	}

	decodedRes := DecodeSecretSharesMessage(&network)

	if compareMessageEquality(message, decodedRes) {
		t.Errorf(
			"Could not decode message with \n"+
				"network: %v\n"+
				"message: %v\n"+
				"decoded: %v\n",
			network, message, decodedRes,
		)
	} else {
		fmt.Println("successfully decoded message")
	}

}
