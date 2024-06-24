package testbase

import (
	"crypto/sha256"
	"fmt"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/hash/sha2"
	"github.com/consensys/gnark/std/math/uints"
)

type sha2Circuit struct {
	In       []uints.U8
	Expected [32]uints.U8
}

func (c *sha2Circuit) Define(api frontend.API) error {

	h, err := sha2.New(api)
	if err != nil {
		return err
	}
	uapi, err := uints.New[uints.U32](api)
	if err != nil {
		return err
	}
	h.Write(c.In)
	res := h.Sum()

	//h2, _ := sha2.New(api)
	//h2.Write(res)
	//rres := h2.Sum()

	if len(res) != 32 {
		return fmt.Errorf("not 32 bytes")
	}
	for i := range c.Expected {
		uapi.ByteAssertEq(c.Expected[i], res[i])
	}
	return nil
}

func T_sha256(len int) {
	bts := make([]byte, len)
	//fmt.Println(bts)
	dgst := sha256.Sum256(bts)

	//dgst = sha256.Sum256(dgst[:])
	//fmt.Println(dgst)
	circuit := sha2Circuit{
		In: uints.NewU8Array(bts),
	}
	copy(circuit.Expected[:], uints.NewU8Array(dgst[:]))
	//
	//fmt.Println(circuit.In)

	r1cs, _ := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	pk, vk, _ := groth16.Setup(r1cs)
	//

	assignment := sha2Circuit{
		In: uints.NewU8Array(bts),
	}
	copy(assignment.Expected[:], uints.NewU8Array(dgst[:]))

	witness, _ := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	publicWitness, _ := witness.Public()
	proof, _ := groth16.Prove(r1cs, pk, witness)
	err := groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		fmt.Println("invalid proof")
	}
}
