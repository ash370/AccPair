package base

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/math/bitslice"
)

type partitionCircuit struct {
	Split                  uint
	In, ExpLower, ExpUpper frontend.Variable
}

func (c *partitionCircuit) Define(api frontend.API) error {
	lower, upper := bitslice.Partition(api, c.In, c.Split)
	api.AssertIsEqual(lower, c.ExpLower)
	api.AssertIsEqual(upper, c.ExpUpper)
	return nil
}

func T_part() {
	assignment := partitionCircuit{
		Split:    16,
		In:       0xffff1234,
		ExpUpper: 0xffff,
		ExpLower: 0x1234,
	}

	var circuit partitionCircuit
	circuit.Split = 16

	r1cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)

	pk, vk, err := groth16.Setup(r1cs)

	witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	publicWitness, err := witness.Public()

	proof, err := groth16.Prove(r1cs, pk, witness)

	err = groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		// invalid proof
	}
}
