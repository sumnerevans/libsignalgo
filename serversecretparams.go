package libsignalgo

/*
#cgo LDFLAGS: ./libsignal/target/release/libsignal_ffi.a -ldl
#include "./libsignal/libsignal-ffi.h"
*/
import "C"
import "unsafe"

type ServerSecretParams [2305]byte

var _ = ffiTypeSizeMustMatch(ServerSecretParams{}, C.SignalSERVER_SECRET_PARAMS_LEN)

func GenerateServerSecretParams() (ServerSecretParams, error) {
	randomness, err := GenerateRandomness()
	if err != nil {
		return ServerSecretParams{}, err
	}

	return GenerateServerSecretParamsWithRandomness(randomness)
}

func GenerateServerSecretParamsWithRandomness(randomness Randomness) (ServerSecretParams, error) {
	secretParams := ServerSecretParams{}

	signalFfiError := C.signal_server_secret_params_generate_deterministic(
		(*[C.SignalSERVER_SECRET_PARAMS_LEN]C.uchar)(unsafe.Pointer(&secretParams[0])),
		(*[C.SignalRANDOMNESS_LEN]C.uchar)(unsafe.Pointer(&randomness[0])))
	if signalFfiError != nil {
		return secretParams, wrapError(signalFfiError)
	}

	return secretParams, nil
}

func (ssp ServerSecretParams) GetPublicParams() (ServerPublicParams, error) {
	publicParams := ServerPublicParams{}

	signalFfiError := C.signal_server_secret_params_get_public_params(
		(*[C.SignalSERVER_PUBLIC_PARAMS_LEN]C.uchar)(unsafe.Pointer(&publicParams[0])),
		(*[C.SignalSERVER_SECRET_PARAMS_LEN]C.uchar)(unsafe.Pointer(&ssp[0])))
	if signalFfiError != nil {
		return publicParams, wrapError(signalFfiError)
	}

	return publicParams, nil
}
