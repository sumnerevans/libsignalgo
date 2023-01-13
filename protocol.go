package libsignalgo

/*
#cgo LDFLAGS: ./libsignal/target/release/libsignal_ffi.a -ldl
#include "./libsignal/libsignal-ffi.h"
*/
import "C"
import gopointer "github.com/mattn/go-pointer"

func Encrypt(plaintext []byte, forAddress *Address, sessionStore SessionStore, identityKeyStore IdentityKeyStore, context StoreContext) (*CiphertextMessage, error) {
	var ciphertextMessage *C.SignalCiphertextMessage

	contextPointer := gopointer.Save(context)
	defer gopointer.Unref(contextPointer)

	signalFfiError := C.signal_encrypt_message(
		&ciphertextMessage,
		BytesToBuffer(plaintext),
		forAddress.ptr,
		wrapSessionStore(sessionStore),
		wrapIdentityKeyStore(identityKeyStore),
		contextPointer,
	)
	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}
	return wrapCiphertextMessage(ciphertextMessage), nil
}
