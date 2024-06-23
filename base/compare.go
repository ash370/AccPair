package base

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/math/cmp"
)

type cmpCircuit struct {
	ID1 frontend.Variable
	IDk frontend.Variable
	Id  frontend.Variable
}

func (c *cmpCircuit) Define(api frontend.API) error {
	api.AssertIsEqual(cmp.IsLessOrEqual(api, c.Id, c.IDk), 1)
	api.AssertIsEqual(cmp.IsLessOrEqual(api, c.ID1, c.Id), 1)

	return nil
}

func T_cmp() {
	assignment := cmpCircuit{
		ID1: 1,
		IDk: 10,
		Id:  8,
	}

	var circuit cmpCircuit
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
