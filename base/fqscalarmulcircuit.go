package base

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
)

type fqscalarmulCircuit struct {
	ExpectedCt1 sw_bn254.G1Affine `gnark:",public"`
	T1          frontend.Variable
	C           sw_bn254.G1Affine
}

func (circuit *fqscalarmulCircuit) Define(api frontend.API) error {

	return nil
}
