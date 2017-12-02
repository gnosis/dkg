package dkg

import "hash"
import "testing"
import "reflect"
import "crypto/elliptic"
import "crypto/sha256"
import "encoding/base64"
import "math/big"

func GetValidNodeParamsForTesting(t *testing.T) (
	curve elliptic.Curve,
	hash hash.Hash,
	g2x *big.Int,
	g2y *big.Int,
	secretPoly1 ScalarPolynomial,
	secretPoly2 ScalarPolynomial,
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

	secretPoly1 = ScalarPolynomial{big.NewInt(1), big.NewInt(2), big.NewInt(3), big.NewInt(4)}
	secretPoly2 = ScalarPolynomial{big.NewInt(5), big.NewInt(6), big.NewInt(7), big.NewInt(8)}
	return
}

func TestInvalidNodeConstruction(t *testing.T) {
	curve, hash, g2x, g2y, secretPoly1, secretPoly2 := GetValidNodeParamsForTesting(t)
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
				secretPoly1, secretPoly2,
			)
			if node != nil && err == nil {
				t.Errorf(
					"Able to create node with invalid g2:\n"+
						"curve: %v\n"+
						"hash: %T\n"+
						"g2: %v, %v\n"+
						"secretPoly1: %v\n"+
						"secretPoly2: %v\n",
					curve.Params().Name, hash, bad.x, bad.y, secretPoly1, secretPoly2,
				)
			} else if reflect.TypeOf(err) != reflect.TypeOf((*InvalidCurvePointError)(nil)).Elem() {
				t.Errorf(
					"Got unexpected error from construction with invalid g2:\n"+
						"curve: %v\n"+
						"hash: %T\n"+
						"g2: %x\n"+
						"secretPoly1: %v\n"+
						"secretPoly2: %v\n",
					"%v\n",
					curve.Params().Name, hash, bad.x, bad.y, secretPoly1, secretPoly2, err,
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
				curve,
				hash,
				g2x, g2y,
				bad.poly1, bad.poly2,
			)
			if node != nil && err == nil {
				t.Errorf(
					"Able to create node with invalid polynomials:\n"+
						"curve: %v\n"+
						"hash: %T\n"+
						"g2: %v, %v\n"+
						"secretPoly1: %v\n"+
						"secretPoly2: %v\n",
					curve.Params().Name, hash, g2x, g2y, bad.poly1, bad.poly2,
				)
			} else if reflect.TypeOf(err) != reflect.TypeOf((*InvalidCurveScalarPolynomialError)(nil)).Elem() {
				t.Errorf(
					"Got unexpected error from construction with invalid polynomials:\n"+
						"curve: %v\n"+
						"hash: %T\n"+
						"g2: %x\n"+
						"secretPoly1: %v\n"+
						"secretPoly2: %v\n",
					"%v\n",
					curve.Params().Name, hash, g2x, g2y, bad.poly1, bad.poly2, err,
				)
			}
		}
	})
}

func TestValidNode(t *testing.T) {
	curve, hash, g2x, g2y, secretPoly1, secretPoly2 := GetValidNodeParamsForTesting(t)

	node, err := NewNode(
		curve,
		hash,
		g2x, g2y,
		secretPoly1, secretPoly2,
	)

	if node == nil || err != nil {
		t.Errorf(
			"Could not create new node with params:\n"+
				"curve: %v\n"+
				"hash: %T\n"+
				"g2: %x\n"+
				"secretPoly1: %v\n"+
				"secretPoly2: %v\n",
			"%v\n",
			curve, hash, g2x, g2y, secretPoly1, secretPoly2, err,
		)
	} else {
		t.Run("PublicKeyPart", func(t *testing.T) {
			pubx, puby := node.PublicKeyPart()
			pubkeypt := base64.StdEncoding.EncodeToString(elliptic.Marshal(curve, pubx, puby))
			if pubkeypt != "BGsX0fLhLEJH+Lzm5WOkQPJ3A32BLeszoPShOUXYmMKWT+NC4v4af5uO5+tKfA+eFivOM1drMV7Oy7ZAaDe/UfU=" {
				t.Errorf("Got unexpected public key part %v", pubkeypt)
			}
		})
	}
}
