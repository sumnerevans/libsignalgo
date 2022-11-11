package libsignalgo

/*
#cgo LDFLAGS: ./libsignal/target/release/libsignal_ffi.a -ldl
#include "./libsignal/libsignal-ffi.h"
*/
import "C"
import (
	"unsafe"
)

type PublicKey struct {
	nativePointer *C.SignalPublicKey
}

func (k *PublicKey) Destroy() error {
	signalFfiError := C.signal_publickey_destroy(k.nativePointer)
	if signalFfiError != nil {
		return wrapError(signalFfiError)
	}
	return nil
}

func (k *PublicKey) Bytes() ([]byte, error) {
	var pub *C.uchar
	var length C.ulong
	signalFfiError := C.signal_publickey_get_public_key_bytes(&pub, &length, k.nativePointer)
	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}
	return C.GoBytes(unsafe.Pointer(pub), C.int(length)), nil
}
