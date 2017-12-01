package dkg

import "hash"
import "testing"
import "reflect"
import "crypto/elliptic"
import "crypto/sha256"
import "encoding/base64"
import "math/big"

func GetValidParams(t *testing.T) (
	curve elliptic.Curve,
	hash hash.Hash,
	g2x *big.Int,
	g2y *big.Int,
	private *big.Int,
) {
	curve = elliptic.P256()
	hash = sha256.New()

	var success bool
	if g2x, success = new(big.Int).SetString("0a5d23f079fed8f443d7fa87d70849f846f941c07d77b1e1df139e8f7ff61a70", 16); !success {
		t.Errorf("Could not initialize g2x")
	}
	if g2y, success = new(big.Int).SetString("608e4edf904f2e1d5f54ddc708afec01fd2287fc95555139e065cbad4d5ecdba", 16); !success {
		t.Errorf("Could not initialize g2y")
	}

	private = big.NewInt(1)
	return
}

func TestInvalidNodeConstruction(t *testing.T) {
	curve, hash, g2x, g2y, private := GetValidParams(t)
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
				curve,
				hash,
				bad.x, bad.y,
				private,
			)
			if node != nil && err == nil {
				t.Errorf(
					"Able to create node with invalid g2:\n"+
						"curve: %v\n"+
						"hash: %T\n"+
						"g2: %v, %v\n"+
						"private: %v\n",
					curve.Params().Name, hash, bad.x, bad.y, private,
				)
			} else if reflect.TypeOf(err) != reflect.TypeOf((*InvalidCurvePointError)(nil)).Elem() {
				t.Errorf(
					"Got unexpected error from construction with invalid g2:\n"+
						"curve: %v\n"+
						"hash: %T\n"+
						"g2: %x\n"+
						"private: %v\n",
					"%v\n",
					curve.Params().Name, hash, bad.x, bad.y, private, err,
				)
			}
		}
	})

	t.Run("Invalid polynomials", func(t *testing.T) {
	})
}

func TestValidNode(t *testing.T) {
	curve, hash, g2x, g2y, private := GetValidParams(t)

	node, err := NewNode(
		curve,
		hash,
		g2x, g2y,
		private,
	)

	if node == nil || err != nil {
		t.Errorf(
			"Could not create new node with params:\n"+
				"curve: %v\n"+
				"hash: %T\n"+
				"g2: %x\n"+
				"private: %v\n",
			"%v\n",
			curve, hash, g2x, g2y, private, err,
		)
	} else {
		t.Run("PublicKey", func(t *testing.T) {
			pubx, puby := node.PublicKey()
			pubkey := base64.StdEncoding.EncodeToString(elliptic.Marshal(curve, pubx, puby))
			if pubkey != "BGsX0fLhLEJH+Lzm5WOkQPJ3A32BLeszoPShOUXYmMKWT+NC4v4af5uO5+tKfA+eFivOM1drMV7Oy7ZAaDe/UfU=" {
				t.Errorf("Got unexpected public key %v", pubkey)
			}
		})
	}
}
