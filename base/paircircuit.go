package base

import (
	"crypto/rand"
	"fmt"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
)

type pairCircuit struct {
	InG1 sw_bn254.G1Affine
	InG2 sw_bn254.G2Affine
	Res  sw_bn254.GTEl
}

func (circuit *pairCircuit) Define(api frontend.API) error {
	pairing, err := sw_bn254.NewPairing(api)
	if err != nil {
		return fmt.Errorf("new pairing: %w", err)
	}

	pairing.AssertIsOnG1(&circuit.InG1)
	pairing.AssertIsOnG2(&circuit.InG2)

	res, err := pairing.Pair([]*sw_bn254.G1Affine{&circuit.InG1}, []*sw_bn254.G2Affine{&circuit.InG2})
	if err != nil {
		return fmt.Errorf("pair: %w", err)
	}
	pairing.AssertIsEqual(res, &circuit.Res)

	return nil
}

func T_paircircuit() {
	_, _, G1AffGen, G2AffGen := bn254.Generators()
	mod := bn254.ID.ScalarField()
	s1, err := rand.Int(rand.Reader, mod)
	if err != nil {
		panic(err)
	}
	s2, err := rand.Int(rand.Reader, mod)
	if err != nil {
		panic(err)
	}
	var p bn254.G1Affine
	p.ScalarMultiplication(&G1AffGen, s1)
	var q bn254.G2Affine
	q.ScalarMultiplication(&G2AffGen, s2)

	res, err := bn254.Pair([]bn254.G1Affine{p}, []bn254.G2Affine{q})

	assignment := pairCircuit{
		InG1: sw_bn254.NewG1Affine(p),
		InG2: sw_bn254.NewG2Affine(q),
		Res:  sw_bn254.NewGTEl(res),
	}

	var circuit pairCircuit
	r1cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)

	pk, vk, err := groth16.Setup(r1cs)

	witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	publicWitness, err := witness.Public()

	//writer := bufio.NewWriter(outputFile)
	proof, err := groth16.Prove(r1cs, pk, witness)
	//size, _ := proof.WriteTo(writer)

	err = groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		// invalid proof
	}
}
