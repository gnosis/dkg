package dkg

import "testing"
import "reflect"
import "crypto/elliptic"
import "crypto/sha256"
import "encoding/base64"
import "math/big"

func TestInvalidNodeConstruction(t *testing.T) {
	curve := elliptic.P256()
	hash := sha256.New()
	g2x, g2y := curve.ScalarBaseMult([]byte{100})
	private := big.NewInt(1)

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
}

func TestValidNode(t *testing.T) {
	curve := elliptic.P256()
	hash := sha256.New()
	g2x, g2y := curve.ScalarBaseMult([]byte{100})
	private := big.NewInt(1)

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
