package libsignalgo

/*
#cgo LDFLAGS: ./libsignal/target/release/libsignal_ffi.a -ldl
#include "./libsignal/libsignal-ffi.h"
*/
import "C"
import (
	"crypto/rand"
	"errors"
)

type Randomness [32]byte

var _ = ffiTypeSizeMustMatch(Randomness{}, C.SignalRANDOMNESS_LEN)

func GenerateRandomness() (Randomness, error) {
	data := Randomness{}
	nread, err := rand.Reader.Read(data[:])
	if err != nil {
		return data, err
	}

	if nread != len(data) {
		return data, errors.New("failed to generate enough random bits")
	}

	return data, nil
}
