package oath

// #cgo LDFLAGS: -loath
// #include <liboath/oath.h>
// #include <stdlib.h>
import "C"

import (
	"encoding/base32"
	"errors"
	"time"
	"unsafe"
)

// This function initializes the OATH library. Every user of this library needs
// to call this function before using other functions. You should call
// oath.Done() when use of the OATH library is no longer needed.
func Init() {
	C.oath_init()
}

// This function deinitializes the OATH library, which were initialized using
// oath.Init(). After calling this function, no other OATH library function may
// be called except for to re-initialize the library using oath.Init().
func Done() {
	C.oath_done()
}

// TOTPValidate validates an OTP for the current unix time.
//
//		secret is a base32 encoded secret key.
//		timeStep is the duration in which an OTP is valid. Typically 30 seconds.
//		window determines how many OTPs after/before start OTP to test.
//		otp is the one-time-password to check for validity.
//
// Returns an error if OTP is invalid.
func TOTPValidate(secret string, timeStep, window uint, otp string) error {
	// Decode base32 encoded string
	bsecret, err := base32.StdEncoding.DecodeString(secret)
	if err != nil {
		return err
	}

	// Convert secret to char array
	csecret := C.CString(string(bsecret))
	defer C.free(unsafe.Pointer(csecret))

	// Convert otp to char array
	cotp := C.CString(otp)
	defer C.free(unsafe.Pointer(cotp))

	r := int(C.oath_totp_validate(csecret,
		C.size_t(len(bsecret)),
		C.time_t(time.Now().Unix()),
		C.uint(timeStep),
		C.time_t(0),
		C.size_t(window),
		cotp))
	// Check if error occured
	if r < 0 {
		return errors.New("OTP is invalid or an error occured.")
	}
	return nil
}

// TOTPGenerate generates an OTP for the current unix time.
//
//		secret is a base32 encoded secret key.
//		timeStep is the duration in which an OTP is valid. Typically 30 seconds.
//		digits is the requested number of digits for the generated OTP.
//
// Returns an OTP.
func TOTPGenerate(secret string, timeStep, digits uint) (string, error) {
	// Decode base32 encoded string
	bsecret, err := base32.StdEncoding.DecodeString(secret)
	if err != nil {
		return "", err
	}

	// Convert secret to char array
	csecret := C.CString(string(bsecret))
	defer C.free(unsafe.Pointer(csecret))

	var cotp = make([]C.char, digits)

	r := int(C.oath_totp_generate(csecret,
		C.size_t(len(bsecret)),
		C.time_t(time.Now().Unix()),
		C.uint(timeStep),
		C.time_t(0),
		C.uint(digits),
		&cotp[0]))

	// Check if error occured
	if r < 0 {
		return "", errors.New("Can't generate OTP")
	}

	otp := C.GoString(&cotp[0])
	return otp, nil
}
