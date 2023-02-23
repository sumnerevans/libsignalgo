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

type ClientZkAuthOperations struct {
	serverPublicParams ServerPublicParams
}

func NewClientZkAuthOperations(serverPublicParams ServerPublicParams) ClientZkAuthOperations {
	return ClientZkAuthOperations{
		serverPublicParams: serverPublicParams,
	}
}

func (self *ClientZkAuthOperations) ReceiveAuthCredential(uuid uuid.UUID, redemptionTime uint32, authCredentialResponse AuthCredentialResponse) (AuthCredential, error) {
	authCredential := AuthCredential{}

	uuidBytes, err := uuid.MarshalBinary()
	if err != nil {
		return authCredential, err
	}

	signalFfiError := C.signal_server_public_params_receive_auth_credential(
		(*[C.SignalAUTH_CREDENTIAL_LEN]C.uchar)(unsafe.Pointer(&authCredential[0])),
		(*[C.SignalSERVER_PUBLIC_PARAMS_LEN]C.uchar)(unsafe.Pointer(&self.serverPublicParams[0])),
		(*[16]C.uchar)(unsafe.Pointer(&uuidBytes[0])),
		C.uint(redemptionTime),
		(*[C.SignalAUTH_CREDENTIAL_RESPONSE_LEN]C.uchar)(unsafe.Pointer(&authCredentialResponse[0])))
	if signalFfiError != nil {
		return authCredential, wrapError(signalFfiError)
	}

	return authCredential, nil
}

func (self *ClientZkAuthOperations) CreateAuthCredentialPresentationWithRandomness(randomness Randomness, groupSecretParams GroupSecretParams, authCredential AuthCredential) (AuthCredentialPresentation, error) {
	authCredentialPresentation := AuthCredentialPresentation{}

	/*
		SignalFfiError *signal_server_public_params_create_auth_credential_presentation_deterministic(const unsigned char **out,
		                                                                                              size_t *out_len,
		                                                                                              const unsigned char (*server_public_params)[SignalSERVER_PUBLIC_PARAMS_LEN],
		                                                                                              const uint8_t (*randomness)[SignalRANDOMNESS_LEN],
		                                                                                              const unsigned char (*group_secret_params)[SignalGROUP_SECRET_PARAMS_LEN],
		                                                                                              const unsigned char (*auth_credential)[SignalAUTH_CREDENTIAL_LEN]);
	*/

	return authCredentialPresentation, nil
}
