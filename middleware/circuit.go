package middleware

//plonk:only verify
//Sha256(1KB)+ECDSA+Sha256(52B)+partition
//Sha256(4KB)+ECDSA+Sha256(52B)+partition
//T_part()+T_sha256_plonk(len)+T_ecdsa_Plonk()

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"log"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	eccecdsa "github.com/consensys/gnark-crypto/ecc/secp256k1/ecdsa"
	"github.com/consensys/gnark/backend/plonk"
	cs "github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/hash/sha2"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/std/signature/ecdsa"
	"github.com/consensys/gnark/test/unsafekzg"
)

type sha2CircuitPlonk struct {
	In       []uints.U8
	Expected [32]uints.U8
}

func (c *sha2CircuitPlonk) Define(api frontend.API) error {

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

func T_sha256_plonk(len int) {
	bts := make([]byte, len)
	//fmt.Println(bts)
	dgst := sha256.Sum256(bts)

	//dgst = sha256.Sum256(dgst[:])
	//fmt.Println(dgst)
	circuit := sha2CircuitPlonk{
		In: uints.NewU8Array(bts),
	}
	copy(circuit.Expected[:], uints.NewU8Array(dgst[:]))

	witness := sha2CircuitPlonk{
		In: uints.NewU8Array(bts),
	}
	copy(witness.Expected[:], uints.NewU8Array(dgst[:]))

	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &circuit)
	if err != nil {
		fmt.Println("circuit compilation error")
	}

	scs := ccs.(*cs.SparseR1CS)
	srs, srsLagrange, err := unsafekzg.NewSRS(scs)
	if err != nil {
		panic(err)
	}

	witnessFull, err := frontend.NewWitness(&witness, ecc.BN254.ScalarField())
	if err != nil {
		log.Fatal(err)
	}

	witnessPublic, err := frontend.NewWitness(&witness, ecc.BN254.ScalarField(), frontend.PublicOnly())
	if err != nil {
		log.Fatal(err)
	}

	pk, vk, err := plonk.Setup(ccs, srs, srsLagrange)
	if err != nil {
		log.Fatal(err)
	}

	proof, err := plonk.Prove(ccs, pk, witnessFull)
	if err != nil {
		log.Fatal(err)
	}

	err = plonk.Verify(proof, vk, witnessPublic)
	if err != nil {
		log.Fatal(err)
	}
}

type EcdsaCircuitPlonk[T, S emulated.FieldParams] struct {
	Sig ecdsa.Signature[S]
	Msg emulated.Element[S]
	Pub ecdsa.PublicKey[T, S]
}

func (c *EcdsaCircuitPlonk[T, S]) Define(api frontend.API) error {
	c.Pub.Verify(api, sw_emulated.GetCurveParams[T](), &c.Msg, &c.Sig)
	return nil
}

func T_ecdsa_Plonk() {
	// generate parameters
	privKey, _ := eccecdsa.GenerateKey(rand.Reader)
	publicKey := privKey.PublicKey

	// sign
	//msg := []byte("testing ECDSA (sha256)") //22byte
	msg := make([]byte, 521)
	md := sha256.New()
	sigBin, _ := privKey.Sign(msg, md)

	// check that the signature is correct
	flag, _ := publicKey.Verify(sigBin, msg, md)
	if !flag {
		fmt.Println("can't verify signature")
	}

	// unmarshal signature
	var sig eccecdsa.Signature
	sig.SetBytes(sigBin)
	r, s := new(big.Int), new(big.Int)
	r.SetBytes(sig.R[:32])
	s.SetBytes(sig.S[:32])

	// compute the hash of the message as an integer
	dataToHash := make([]byte, len(msg))
	copy(dataToHash[:], msg[:])
	md.Reset()
	md.Write(dataToHash[:])
	hramBin := md.Sum(nil)
	hash := eccecdsa.HashToInt(hramBin)

	circuit := EcdsaCircuitPlonk[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{}

	/*witness*/
	assignment := EcdsaCircuitPlonk[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{
		Sig: ecdsa.Signature[emulated.Secp256k1Fr]{
			R: emulated.ValueOf[emulated.Secp256k1Fr](r),
			S: emulated.ValueOf[emulated.Secp256k1Fr](s),
		},
		Msg: emulated.ValueOf[emulated.Secp256k1Fr](hash),
		Pub: ecdsa.PublicKey[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{
			X: emulated.ValueOf[emulated.Secp256k1Fp](privKey.PublicKey.A.X),
			Y: emulated.ValueOf[emulated.Secp256k1Fp](privKey.PublicKey.A.Y),
		},
	}

	// // building the circuit...
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

	proof, err := plonk.Prove(ccs, pk, witnessFull)
	if err != nil {
		log.Fatal(err)
	}

	err = plonk.Verify(proof, vk, witnessPublic)
	if err != nil {
		log.Fatal(err)
	}
}
