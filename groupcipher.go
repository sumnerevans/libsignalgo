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

var UUIDLen = sizeMustMatch(C.SignalUUID_LEN, 16)

func GroupEncrypt(ptext []byte, sender *Address, distributionID uuid.UUID, store SenderKeyStore, context StoreContext) (*CiphertextMessage, error) {
	var ciphertextMessage *C.SignalCiphertextMessage
	signalFfiError := C.signal_group_encrypt_message(
		&ciphertextMessage,
		sender.ptr,
		(*[C.SignalUUID_LEN]C.uchar)(unsafe.Pointer(&distributionID)),
		BytesToBuffer(ptext),
		wrapSenderKeyStore(store),
		unsafe.Pointer(&context))
	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}
	return wrapCiphertextMessage(ciphertextMessage), nil
}

func GroupDecrypt(ctext []byte, sender *Address, store SenderKeyStore, context StoreContext) ([]byte, error) {
	var resp *C.uchar
	var length C.ulong
	signalFfiError := C.signal_group_decrypt_message(
		&resp,
		&length,
		sender.ptr,
		BytesToBuffer(ctext),
		wrapSenderKeyStore(store),
		unsafe.Pointer(&context))
	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}
	return CopyBufferToBytes(resp, length), nil
}
