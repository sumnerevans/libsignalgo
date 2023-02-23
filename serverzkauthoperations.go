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

type ServerZkAuthOperations struct {
	serverSecretParams ServerSecretParams
}

func NewServerZkAuthOperations(serverSecretParams ServerSecretParams) ServerZkAuthOperations {
	return ServerZkAuthOperations{
		serverSecretParams: serverSecretParams,
	}
}

func (self *ServerZkAuthOperations) IssueAuthCredential(uuid uuid.UUID, redemptionTime uint32) (AuthCredentialResponse, error) {
	randomness, err := GenerateRandomness()
	if err != nil {
		return AuthCredentialResponse{}, err
	}

	return self.IssueAuthCredentialWithRandomness(randomness, uuid, redemptionTime)
}

func (self *ServerZkAuthOperations) IssueAuthCredentialWithRandomness(randomness Randomness, uuid uuid.UUID, redemptionTime uint32) (AuthCredentialResponse, error) {
	response := AuthCredentialResponse{}

	uuidBytes, err := uuid.MarshalBinary()
	if err != nil {
		return response, err
	}

	signalFfiError := C.signal_server_secret_params_issue_auth_credential_deterministic(
		(*[C.SignalAUTH_CREDENTIAL_RESPONSE_LEN]C.uchar)(unsafe.Pointer(&response[0])),
		(*[C.SignalSERVER_SECRET_PARAMS_LEN]C.uchar)(unsafe.Pointer(&self.serverSecretParams[0])),
		(*[C.SignalRANDOMNESS_LEN]C.uchar)(unsafe.Pointer(&randomness[0])),
		(*[16]C.uchar)(unsafe.Pointer(&uuidBytes[0])),
		C.uint(redemptionTime))
	if signalFfiError != nil {
		return response, wrapError(signalFfiError)
	}

	return response, nil
}
