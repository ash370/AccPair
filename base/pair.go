package base

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254"
)

func T_pairing() {
	// 定义参数
	c := big.NewInt(3)     // 示例值
	y := big.NewInt(5)     // 示例值
	alpha := big.NewInt(7) // 示例值
	d := big.NewInt(11)    // 示例值

	// 计算 v = c(y + alpha) + d
	v := new(big.Int).Mul(c, new(big.Int).Add(y, alpha))
	v.Add(v, d)

	_, _, g1gen, g2gen := bn254.Generators()

	// 生成 g_0
	var g0 bn254.G1Affine
	g0.Set(&g1gen)

	// 计算 g_0^c, g_0^{y+alpha}, g_0^v
	var g0c, g0_y_alpha, g0v bn254.G1Affine
	g0c.ScalarMultiplication(&g0, c)
	g0_y_alpha.ScalarMultiplication(&g0, new(big.Int).Add(y, alpha))
	g0v.ScalarMultiplication(&g0, v)

	// 计算配对 e(g_0^c, g_0^y g_0^{\alpha}) 和 e(g_0^v, g_0)
	var P [2]bn254.G1Affine
	var Q [2]bn254.G2Affine
	var gt bn254.GT
	// 定义 G2 点
	var g0_g2 bn254.G2Affine
	g0_g2.Set(&g2gen)

	// 计算 e(g_0^c, g_0^{y+\alpha})
	P[0] = g0c
	Q[0].Set(&g2gen)
	Q[0].ScalarMultiplication(&Q[0], new(big.Int).Add(y, alpha))

	// 计算 e(g_0, g_0)^d
	P[1].Set(&g0)
	Q[1].Set(&g2gen)
	Q[1].ScalarMultiplication(&Q[1], d)

	// 执行配对运算
	gt, err := bn254.Pair(P[:], Q[:])
	if err != nil {
		panic(err)
	}

	// 计算 e(g_0^v, g_0)
	var gt_v bn254.GT
	gt_v, err = bn254.Pair([]bn254.G1Affine{g0v}, []bn254.G2Affine{g0_g2})
	if err != nil {
		panic(err)
	}

	// 比较结果
	if gt.Equal(&gt_v) {
		fmt.Println("证明成功，等式成立")
	} else {
		fmt.Println("证明失败，等式不成立")
	}
}
