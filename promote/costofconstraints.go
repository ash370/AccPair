package promote

import (
	"math/big"
	mathrand "math/rand"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	curve "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	ecctedwards "github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/native/twistededwards"
)

func T_promote() {
	curveid := ecctedwards.BN254

	params, _ := twistededwards.GetCurveParams(curveid)

	var g0 curve.PointAffine
	g0.X.SetBigInt(params.Base[0])
	g0.Y.SetBigInt(params.Base[1])

	var assignment promoteCircuit
	assignment.ID1 = 1
	id := 10
	//_id := make([]byte, 1)

	//id := uints.NewU8Array(_id)
	assignment.Id = id
	assignment.IDk = 24

	mathrand.Seed(time.Now().UnixNano())
	randint := mathrand.Intn(1100) + 10
	t := randint
	assignment.Random = t
	bigt := new(big.Int).SetInt64(int64(t))

	var v curve.PointAffine
	v.X.SetBigInt(params.Base[0])
	v.Y.SetBigInt(params.Base[1])
	assignment.Accumulator = twistededwards.Point{X: v.X, Y: v.Y}
	expectedvt := new(curve.PointAffine).ScalarMultiplication(&v, bigt)
	assignment.ExpectedAccmT = twistededwards.Point{X: expectedvt.X, Y: expectedvt.Y}

	d := 100
	dt := d * t
	assignment.D = d
	expecteddt := new(curve.PointAffine).ScalarMultiplication(&g0, new(big.Int).SetInt64(int64(dt)))
	assignment.ExpectedDT = twistededwards.Point{X: expecteddt.X, Y: expecteddt.Y}

	var c curve.PointAffine
	c.X.SetBigInt(params.Base[0])
	c.Y.SetBigInt(params.Base[1])
	assignment.C = twistededwards.Point{X: c.X, Y: c.Y}
	expectedct := new(curve.PointAffine).ScalarMultiplication(&c, bigt)
	assignment.ExpectedCT = twistededwards.Point{X: expectedct.X, Y: expectedct.Y}

	idt := id * t
	expectedidt := new(curve.PointAffine).ScalarMultiplication(&c, new(big.Int).SetInt64(int64(idt)))
	assignment.ExpectedCidT = twistededwards.Point{X: expectedidt.X, Y: expectedidt.Y}

	var circuit promoteCircuit
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
