package dkg

import "fmt"
import "crypto/elliptic"
import "math/big"

type InvalidCurveScalarError struct {
	curve elliptic.Curve
	k     *big.Int
}

func (e InvalidCurveScalarError) Error() string {
	return fmt.Sprintf("dkg: invalid %v scalar %64x",
		e.curve.Params().Name, e.k.Bytes())
}

type InvalidCurvePointError struct {
	curve    elliptic.Curve
	g2x, g2y *big.Int
}

func (e InvalidCurvePointError) Error() string {
	return fmt.Sprintf("dkg: invalid %v point %x",
		e.curve.Params().Name,
		elliptic.Marshal(e.curve, e.g2x, e.g2y),
	)
}
