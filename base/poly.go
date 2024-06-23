package base

import (
	"fmt"
)

// Polynomial represents a polynomial with integer coefficients.
type Polynomial struct {
	Coefficients []int
}

// NewPolynomial creates a new polynomial given a slice of coefficients.
func NewPolynomial(coeffs []int) Polynomial {
	return Polynomial{Coefficients: coeffs}
}

// Degree returns the degree of the polynomial.
func (p Polynomial) Degree() int {
	return len(p.Coefficients) - 1
}

// LeadingCoefficient returns the leading coefficient of the polynomial.
func (p Polynomial) LeadingCoefficient() int {
	if len(p.Coefficients) == 0 {
		return 0
	}
	return p.Coefficients[len(p.Coefficients)-1]
}

// Print prints the polynomial in human-readable form.
func (p Polynomial) Print() {
	for i := len(p.Coefficients) - 1; i >= 0; i-- {
		if i != len(p.Coefficients)-1 && p.Coefficients[i] >= 0 {
			fmt.Print("+")
		}
		fmt.Printf("%dx^%d ", p.Coefficients[i], i)
	}
	fmt.Println()
}

// Divide performs polynomial division and returns the quotient and remainder.
func (p Polynomial) Divide(divisor Polynomial) (Polynomial, Polynomial) {
	var quotientCoeffs []int
	remainder := p

	for remainder.Degree() >= divisor.Degree() {
		leadCoeffRatio := remainder.LeadingCoefficient()
		degreeDiff := remainder.Degree() - divisor.Degree()

		termCoeffs := make([]int, degreeDiff+1)
		termCoeffs[degreeDiff] = leadCoeffRatio
		term := NewPolynomial(termCoeffs)

		fmt.Print("Current term: ")
		term.Print()

		quotientCoeffs = append([]int{leadCoeffRatio}, quotientCoeffs...)

		subtractTerm := term.Multiply(divisor)
		remainder = remainder.Subtract(subtractTerm)

		fmt.Print("Current remainder: ")
		remainder.Print()
	}

	return NewPolynomial(quotientCoeffs), remainder
}

// Multiply multiplies the polynomial by another polynomial.
func (p Polynomial) Multiply(q Polynomial) Polynomial {
	resultCoeffs := make([]int, p.Degree()+q.Degree()+1)

	for i := range p.Coefficients {
		for j := range q.Coefficients {
			resultCoeffs[i+j] += p.Coefficients[i] * q.Coefficients[j]
		}
	}

	return NewPolynomial(resultCoeffs)
}

// Subtract subtracts another polynomial from the polynomial.
func (p Polynomial) Subtract(q Polynomial) Polynomial {
	maxDegree := max(p.Degree(), q.Degree())
	resultCoeffs := make([]int, maxDegree+1)

	for i := range resultCoeffs {
		if i <= p.Degree() {
			resultCoeffs[i] += p.Coefficients[i]
		}
		if i <= q.Degree() {
			resultCoeffs[i] -= q.Coefficients[i]
		}
	}

	for len(resultCoeffs) > 1 && resultCoeffs[len(resultCoeffs)-1] == 0 {
		resultCoeffs = resultCoeffs[:len(resultCoeffs)-1] //delete last zero
	}

	return NewPolynomial(resultCoeffs)
}

// max returns the maximum of two integers.
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func T_poly() {
	// Example usage
	dividend := NewPolynomial([]int{4, 6, 15, 1})
	divisor := NewPolynomial([]int{4, 1})

	fmt.Print("Dividend: ")
	dividend.Print()

	fmt.Print("Divisor: ")
	divisor.Print()

	quotient, remainder := dividend.Divide(divisor)

	fmt.Print("Quotient: ")
	quotient.Print()

	fmt.Print("Remainder: ")
	remainder.Print()
}
