package base

import (
	"bufio"
	"fmt"
	"log"
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/plonk"
	cs "github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/std/math/bitslice"
	"github.com/consensys/gnark/test/unsafekzg"
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
		In:       0xffff1234345,
		ExpUpper: 0xffff123,
		ExpLower: 0x4345,
	}

	var circuit partitionCircuit
	circuit.Split = 16

	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &circuit)
	if err != nil {
		fmt.Println("circuit compilation error")
	}

	scs := ccs.(*cs.SparseR1CS)
	srs, srsLagrange, err := unsafekzg.NewSRS(scs)
	if err != nil {
		panic(err)
	}

	witnessFull, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	if err != nil {
		log.Fatal(err)
	}

	witnessPublic, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField(), frontend.PublicOnly())
	if err != nil {
		log.Fatal(err)
	}

	pk, vk, err := plonk.Setup(ccs, srs, srsLagrange)
	if err != nil {
		log.Fatal(err)
	}

	outputFile, err := os.Create("partition_vk.txt")
	if err != nil {
		fmt.Println("无法创建文件：", err)
		return
	}
	defer outputFile.Close()

	writer := bufio.NewWriter(outputFile)
	size, _ := vk.WriteTo(writer)
	fmt.Println("size of vk(partition):", size)

	proof, err := plonk.Prove(ccs, pk, witnessFull)
	if err != nil {
		log.Fatal(err)
	}

	err = plonk.Verify(proof, vk, witnessPublic)
	if err != nil {
		log.Fatal(err)
	}
}
