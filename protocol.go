package libsignalgo

/*
#cgo LDFLAGS: ./libsignal/target/release/libsignal_ffi.a -ldl
#include "./libsignal/libsignal-ffi.h"
*/
import "C"

// func Encrypt(plaintext []byte, forAddress Address, sessionStore SessionStore, identityStore IdentityKeyStore, context StoreContext) (*messages.CiphertextMessage, error) {
// 	var ciphertextMessage *C.SignalCiphertextMessage
// 	signalFfiError := C.signal_encrypt_message(&ciphertextMessage, BytesToBuffer(plaintext), forAddress.ptr, sessionStore.ptr, identityStore.ptr, context.ptr)
// 	if signalFfiError != nil {
// 		return nil, wrapError(signalFfiError)
// 	}
// 	return wrapCiphertextMessage(ciphertextMessage), nil
// }
