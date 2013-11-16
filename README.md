oath
====

* oath is a light wrapper for liboath library from [oath-toolkit](http://www.nongnu.org/oath-toolkit) project.
* Currently, only TOTP generation and validation functions are implemented.
* See [godoc](http://godoc.org/github.com/tapir/oath) for documentation.

Example
=======
```go
package main

import (
	"fmt"
	"oath"
)

func main() {
	// Init library
	oath.Init()
	defer oath.Done()

	secret := "ABCDEFGHJKLMNOPR"

	// Generate a 6 digit OTP for 30 second time step.
	otp, err := oath.TOTPGenerate(secret, 30, 6)
	if err != nil {
		panic(err)
	}
	fmt.Println(otp)

	// Validate the OTP with 1 time step tolerance
	r, err := oath.TOTPValidate(secret, 30, 1, otp)
	if err != nil {
		panic(err)
	}
	fmt.Println(r) // Should print true
}
```
