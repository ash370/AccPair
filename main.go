package main

import "yoko0612.com/AccPair/testbase"

func main() {
	//base.T_pairing()
	//base.T_poly()
	//base.T_multithread()
	//base.T_scalarmul()
	//base.T_paircircuit() //1054143
	testbase.T_sha256() //521:backend=groth16 nbConstraints=332824 took=3934.296929  backend=plonk nbConstraints=1222358 took=390304.332868
	//52:backend=plonk nbConstraints=601714 took=125561.107672
	//base.T_cmp() //1278+1278=2556
	//base.T_part() //91
	//access.T_access() //15231
	//testbase.T_ecdsa() //plonk:nbConstraints=453838 took=21084.567518 groth16:nbConstraints=122458 took=1625.494955
}
