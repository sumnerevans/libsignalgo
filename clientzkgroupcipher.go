package libsignalgo

/*
#cgo LDFLAGS: ./libsignal/target/release/libsignal_ffi.a -ldl
#include "./libsignal/libsignal-ffi.h"
*/
import "C"

import (
	"unsafe"

	"github.com/google/uuid"
)

type ClientZkGroupCipher struct {
	groupSecretParams GroupSecretParams
}

func NewClientZkGroupCipher(groupSecretParams GroupSecretParams) ClientZkGroupCipher {
	return ClientZkGroupCipher{
		groupSecretParams: groupSecretParams,
	}
}

func (self *ClientZkGroupCipher) EncryptUuid(uuid uuid.UUID) (UuidCiphertext, error) {
	uuidCiphertext := UuidCiphertext{}

	// TODO is this even necessary as the underlying type is [16]byte?
	uuidBytes, err := uuid.MarshalBinary()
	if err != nil {
		return uuidCiphertext, err
	}

	signalFfiError := C.signal_group_secret_params_encrypt_uuid(
		(*[C.SignalUUID_CIPHERTEXT_LEN]C.uchar)(unsafe.Pointer(&uuidCiphertext[0])),
		(*[C.SignalGROUP_SECRET_PARAMS_LEN]C.uchar)(unsafe.Pointer(&self.groupSecretParams[0])),
		(*[16]C.uchar)(unsafe.Pointer(&uuidBytes[0])))
	if signalFfiError != nil {
		return uuidCiphertext, wrapError(signalFfiError)
	}

	return uuidCiphertext, nil
}

func (self *ClientZkGroupCipher) DecryptUuid(uuidCiphertext UuidCiphertext) (uuid.UUID, error) {
	uuid := uuid.UUID{}

	signalFfiError := C.signal_group_secret_params_decrypt_uuid(
		(*[16]C.uchar)(unsafe.Pointer(&uuid[0])),
		(*[C.SignalGROUP_SECRET_PARAMS_LEN]C.uchar)(unsafe.Pointer(&self.groupSecretParams[0])),
		(*[C.SignalUUID_CIPHERTEXT_LEN]C.uchar)(unsafe.Pointer(&uuidCiphertext[0])))
	if signalFfiError != nil {
		return uuid, wrapError(signalFfiError)
	}

	return uuid, nil
}
