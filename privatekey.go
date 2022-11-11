package libsignalgo

/*
#cgo LDFLAGS: ./libsignal/target/release/libsignal_ffi.a -ldl
#include "./libsignal/libsignal-ffi.h"
*/
import "C"
import "unsafe"

type PrivateKey struct {
	nativePointer *C.SignalPrivateKey
}

func GeneratePrivateKey() (*PrivateKey, error) {
	var pk *C.SignalPrivateKey
	signalFfiError := C.signal_privatekey_generate(&pk)
	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}
	return &PrivateKey{nativePointer: pk}, nil
}

func DeserializePrivateKey(keyData []byte) (*PrivateKey, error) {
	var pk *C.SignalPrivateKey
	signalFfiError := C.signal_privatekey_deserialize(&pk, BytesToBuffer(keyData))
	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}
	return &PrivateKey{nativePointer: pk}, nil
}

func (pk *PrivateKey) Clone() (*PrivateKey, error) {
	var cloned *C.SignalPrivateKey
	signalFfiError := C.signal_privatekey_clone(&cloned, pk.nativePointer)
	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}
	return &PrivateKey{nativePointer: cloned}, nil
}

func (pk *PrivateKey) Destroy() error {
	signalFfiError := C.signal_privatekey_destroy(pk.nativePointer)
	if signalFfiError != nil {
		return wrapError(signalFfiError)
	}
	return nil
}

func (pk *PrivateKey) GetPublicKey() (*PublicKey, error) {
	var pub *C.SignalPublicKey
	signalFfiError := C.signal_privatekey_get_public_key(&pub, pk.nativePointer)
	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}
	return &PublicKey{nativePointer: pub}, nil
}

func (pk *PrivateKey) Serialize() ([]byte, error) {
	var serialized *C.uchar
	var length C.ulong
	signalFfiError := C.signal_privatekey_serialize(&serialized, &length, pk.nativePointer)
	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}
	return C.GoBytes(unsafe.Pointer(serialized), C.int(length)), nil
}

func (pk *PrivateKey) Sign(message []byte) ([]byte, error) {
	var signed *C.uchar
	var length C.ulong
	signalFfiError := C.signal_privatekey_sign(&signed, &length, pk.nativePointer, BytesToBuffer(message))
	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}
	return C.GoBytes(unsafe.Pointer(signed), C.int(length)), nil
}

func (pk *PrivateKey) Agree(publicKey *PublicKey) ([]byte, error) {
	var agreed *C.uchar
	var length C.ulong
	signalFfiError := C.signal_privatekey_agree(&agreed, &length, pk.nativePointer, publicKey.nativePointer)
	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}
	return C.GoBytes(unsafe.Pointer(agreed), C.int(length)), nil
}
