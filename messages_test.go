package dkg

import (
	"bytes"
	"fmt"
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

	encodedRes := EncodeSecretSharesMessage(network, message)
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

	// decodedRes := DecodeSecretSharesMessage(network)

	// if &decodedRes != message {
	// 	t.Errorf(
	// 		"Could not decode message with \n"+
	// 			"network: %v\n"+
	// 			"message: %v\n"+
	// 			"decoded: %v\n",
	// 		network, message, decodedRes,
	// 	)
	// } else {
	// 	fmt.Println("successfully decoded message")
	// }

}

// func TestValidMessage(t *testing.T) {
// 	//TODO
// }

// func TestBroadcastPublicInfo(t *testing.T) {
// 	//TODO
// }

// func TestBroadcastPublicKey(t *testing.T) {
// 	//TODO
// }

// func TestBroadcastComplaint(t *testing.T) {
// 	//TODO
// }

// func TestSendPrivateMessage(t *testing.T) [

// ]
