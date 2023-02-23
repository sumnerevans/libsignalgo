package libsignalgo

/*
#cgo LDFLAGS: ./libsignal/target/release/libsignal_ffi.a -ldl
#include "./libsignal/libsignal-ffi.h"
*/
import "C"
import "unsafe"

type GroupSecretParams [289]byte

var _ = ffiTypeSizeMustMatch(GroupSecretParams{}, C.SignalGROUP_SECRET_PARAMS_LEN)

func GenerateGroupSecretParams() (GroupSecretParams, error) {
	randomness, err := GenerateRandomness()
	if err != nil {
		return GroupSecretParams{}, err
	}

	return GenerateGroupSecretParamsWithRandomness(randomness)
}

func GenerateGroupSecretParamsWithRandomness(randomness Randomness) (GroupSecretParams, error) {
	secretParams := GroupSecretParams{}

	signalFfiError := C.signal_group_secret_params_generate_deterministic(
		(*[C.SignalGROUP_SECRET_PARAMS_LEN]C.uchar)(unsafe.Pointer(&secretParams[0])),
		(*[C.SignalRANDOMNESS_LEN]C.uchar)(unsafe.Pointer(&randomness[0])),
	)
	if signalFfiError != nil {
		return secretParams, wrapError(signalFfiError)
	}

	return secretParams, nil
}

func DeriveGroupSecretParamsFromMasterKey(masterKey GroupMasterKey) (GroupSecretParams, error) {
	secretParams := GroupSecretParams{}

	signalFfiError := C.signal_group_secret_params_derive_from_master_key(
		(*[C.SignalGROUP_SECRET_PARAMS_LEN]C.uchar)(unsafe.Pointer(&secretParams[0])),
		(*[C.SignalGROUP_MASTER_KEY_LEN]C.uchar)(unsafe.Pointer(&masterKey[0])),
	)
	if signalFfiError != nil {
		return secretParams, wrapError(signalFfiError)
	}

	return secretParams, nil
}

func (gsp GroupSecretParams) GetMasterKey() (GroupMasterKey, error) {
	masterKey := GroupMasterKey{}

	signalFfiError := C.signal_group_secret_params_get_master_key(
		(*[C.SignalGROUP_MASTER_KEY_LEN]C.uchar)(unsafe.Pointer(&masterKey[0])),
		(*[C.SignalGROUP_SECRET_PARAMS_LEN]C.uchar)(unsafe.Pointer(&gsp[0])),
	)
	if signalFfiError != nil {
		return masterKey, wrapError(signalFfiError)
	}

	return masterKey, nil
}

func (gsp GroupSecretParams) GetPublicParams() (GroupPublicParams, error) {
	publicParams := GroupPublicParams{}

	signalFfiError := C.signal_group_secret_params_get_public_params(
		(*[C.SignalGROUP_PUBLIC_PARAMS_LEN]C.uchar)(unsafe.Pointer(&publicParams[0])),
		(*[C.SignalGROUP_SECRET_PARAMS_LEN]C.uchar)(unsafe.Pointer(&gsp[0])),
	)
	if signalFfiError != nil {
		return publicParams, wrapError(signalFfiError)
	}

	return publicParams, nil
}
