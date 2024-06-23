package base

import (
	"bufio"
	"fmt"
	"math/big"
	mathrand "math/rand"
	"os"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	curve "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	ecctedwards "github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/native/twistededwards"
)

type scalarmulCircuit1 struct {
	Expectresult twistededwards.Point `gnark:",public"`
	A            frontend.Variable
}

func (circuit *scalarmulCircuit1) Define(api frontend.API) error {
	curvepara := ecctedwards.BN254

	curve, err := twistededwards.NewEdCurve(api, curvepara)
	if err != nil {
		return err
	}

	_g, _ := twistededwards.GetCurveParams(curvepara)
	g := twistededwards.Point{X: _g.Base[0], Y: _g.Base[1]}
	res := curve.ScalarMul(g, circuit.A)

	api.AssertIsEqual(circuit.Expectresult.X, res.X)

	return nil
}

type scalarmulCircuit2 struct {
	G            twistededwards.Point
	Expectresult twistededwards.Point `gnark:",public"`
	A            frontend.Variable
}

func (circuit *scalarmulCircuit2) Define(api frontend.API) error {
	curvepara := ecctedwards.BN254

	curve, err := twistededwards.NewEdCurve(api, curvepara)
	if err != nil {
		return err
	}

	res := curve.ScalarMul(circuit.G, circuit.A)

	api.AssertIsEqual(circuit.Expectresult.X, res.X)

	return nil
}

func T_scalarmul1() {
	curveid := ecctedwards.BN254

	params, _ := twistededwards.GetCurveParams(curveid)

	var g curve.PointAffine
	g.X.SetBigInt(params.Base[0])
	g.Y.SetBigInt(params.Base[1])

	mathrand.Seed(time.Now().UnixNano())
	randint := mathrand.Intn(1100) + 10
	a := new(big.Int).Sub(params.Order, big.NewInt(int64(randint)))

	res := new(curve.PointAffine).ScalarMultiplication(&g, a)

	var assignment scalarmulCircuit1

	assignment.A = a
	assignment.Expectresult = twistededwards.Point{X: res.X, Y: res.Y}

	outputFile, err := os.Create("output.txt")
	if err != nil {
		fmt.Println("无法创建文件：", err)
		return
	}
	defer outputFile.Close()

	var circuit scalarmulCircuit1

	r1cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)

	pk, vk, err := groth16.Setup(r1cs)

	witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	publicWitness, err := witness.Public()

	writer := bufio.NewWriter(outputFile)
	proof, err := groth16.Prove(r1cs, pk, witness)
	size, _ := proof.WriteTo(writer)
	if err != nil {
		fmt.Println("写入文件失败：", err)
		return
	}
	fmt.Println("size:", size)

	err = groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		// invalid proof
	}

}

func T_scalarmul() {
	curveid := ecctedwards.BN254

	params, _ := twistededwards.GetCurveParams(curveid)

	var g curve.PointAffine
	g.X.SetBigInt(params.Base[0])
	g.Y.SetBigInt(params.Base[1])

	mathrand.Seed(time.Now().UnixNano())
	randint := mathrand.Intn(1100) + 10
	a := new(big.Int).Sub(params.Order, big.NewInt(int64(randint)))

	len_a := a.BitLen()
	fmt.Println("len of a:", len_a)
	starttime := time.Now()
	res := new(curve.PointAffine).ScalarMultiplication(&g, a)
	endtime := time.Now()
	dur := endtime.Sub(starttime)
	fmt.Printf("time of scalar_mul:%fms:\n\n", dur.Seconds()*1000) //0.1ms

	var assignment scalarmulCircuit2

	assignment.A = a
	assignment.Expectresult = twistededwards.Point{X: res.X, Y: res.Y}
	assignment.G = twistededwards.Point{X: g.X, Y: g.Y}

	var circuit scalarmulCircuit2

	r1cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)

	pk, vk, err := groth16.Setup(r1cs)

	witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	publicWitness, err := witness.Public()
	proof, err := groth16.Prove(r1cs, pk, witness)

	//var proofBuf bytes.Buffer
	//_, err = proof.WriteTo(&proofBuf)
	//if err != nil {
	//	fmt.Println("Error serializing proof:", err)
	//	return
	//}

	// Get the proof size
	//proofSize := proofBuf.Len()
	//fmt.Printf("The proof size is %d bytes\n", proofSize)

	//var s bytes.Buffer
	//b, _ := groth16.NewProof(ecc.BLS12_381).WriteTo(&s)
	//fmt.Println("new proof:", b)
	err = groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		// invalid proof
	}

}
