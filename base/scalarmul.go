package base

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"runtime"
	"sync"
	"time"

	"github.com/consensys/gnark-crypto/ecc/bn254"
)

const n = 1048576

// worker function calculates the square of a number and sends the result to the channel
/*func worker(num int, wg *sync.WaitGroup, results chan<- int) {
	defer wg.Done() // Notify the WaitGroup that this goroutine is done
	square := num * num
	results <- square // Send the result to the channel
}*/
func worker(scalar *big.Int, wg *sync.WaitGroup, results chan<- bn254.G1Affine) {
	defer wg.Done() // Notify the WaitGroup that this goroutine is done
	scalarmul := new(bn254.G1Affine).ScalarMultiplicationBase(scalar)
	results <- *scalarmul // Send the result to the channel
}

func T_multithread() {
	numCPU := runtime.GOMAXPROCS(0)
	fmt.Printf("当前 GOMAXPROCS: %d\n", numCPU)

	nums := make([]big.Int, 0, n)
	for i := 0; i < n; i++ {
		_num, _ := rand.Int(rand.Reader, bn254.ID.BaseField())
		//fmt.Println("_num:", _num)
		num := new(big.Int).Mod(new(big.Int).Add(big.NewInt(int64(4)), _num), bn254.ID.BaseField())
		nums = append(nums, *num)
	}

	// Channel to collect results
	results := make(chan bn254.G1Affine, len(nums))

	// WaitGroup to wait for all goroutines to finish
	var wg sync.WaitGroup

	// Launch a worker goroutine for each number
	starttime := time.Now()
	for _, num := range nums {
		wg.Add(1)
		go worker(&num, &wg, results)
	}

	// Wait for all goroutines to finish
	go func() {
		wg.Wait()
		close(results) // Close the results channel once all goroutines are done
	}()
	endtime := time.Now()
	fmt.Println("time cost:", endtime.Sub(starttime).Seconds())

	// Collect and print the results
	var ret bn254.G1Affine
	start := time.Now()
	for result := range results {
		//fmt.Println(result)
		ret = *ret.Add(&ret, &result)
	}
	end := time.Now()
	fmt.Println("time cost:", end.Sub(start).Seconds())
	//fmt.Println(ret)

}
