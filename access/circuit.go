package access

import (
	ecctedwards "github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/native/twistededwards"
	"github.com/consensys/gnark/std/math/cmp"
)

type accessCircuit struct {
	ID1           frontend.Variable
	Id            frontend.Variable
	IDk           frontend.Variable
	Random        frontend.Variable
	Accumulator   twistededwards.Point //X->Leaf
	D             frontend.Variable
	C             twistededwards.Point
	ExpectedAccmT twistededwards.Point `gnark:",public"`
	ExpectedDT    twistededwards.Point `gnark:",public"`
	ExpectedCT    twistededwards.Point `gnark:",public"`
	ExpectedCidT  twistededwards.Point `gnark:",public"`
}

func (c *accessCircuit) Define(api frontend.API) error {
	api.AssertIsEqual(cmp.IsLessOrEqual(api, c.Id, c.IDk), 1)
	api.AssertIsEqual(cmp.IsLessOrEqual(api, c.ID1, c.Id), 1)

	curvepara := ecctedwards.BN254
	curve, err := twistededwards.NewEdCurve(api, curvepara)
	if err != nil {
		return err
	}

	_g0, _ := twistededwards.GetCurveParams(curvepara)
	g0 := twistededwards.Point{X: _g0.Base[0], Y: _g0.Base[1]}

	expectedaccmt := curve.ScalarMul(c.Accumulator, c.Random)
	api.AssertIsEqual(expectedaccmt.X, c.ExpectedAccmT.X)

	expecteddt := curve.ScalarMul(g0, api.Mul(c.D, c.Random))
	api.AssertIsEqual(expecteddt.X, c.ExpectedDT.X)

	expectedct := curve.ScalarMul(c.C, c.Random)
	api.AssertIsEqual(expectedct.X, c.ExpectedCT.X)

	expectedcidt := curve.ScalarMul(c.C, api.Mul(c.Id, c.Random))
	api.AssertIsEqual(expectedcidt.X, c.ExpectedCidT.X)

	return nil
}
