package libsignalgo

/*
#cgo LDFLAGS: ./libsignal/target/release/libsignal_ffi.a -ldl
#include "./libsignal/libsignal-ffi.h"
*/
import "C"
import (
	"runtime"
	"unsafe"

	"github.com/google/uuid"
)

type SenderKeyDistributionMessage struct {
	ptr *C.SignalSenderKeyDistributionMessage
}

func wrapSenderKeyDistributionMessage(ptr *C.SignalSenderKeyDistributionMessage) *SenderKeyDistributionMessage {
	sc := &SenderKeyDistributionMessage{ptr: ptr}
	runtime.SetFinalizer(sc, (*SenderKeyDistributionMessage).Destroy)
	return sc
}

func NewSenderKeyDistributionMessage(sender *Address, distributionID uuid.UUID, store SenderKeyStore, context StoreContext) (*SenderKeyDistributionMessage, error) {
	var skdm *C.SignalSenderKeyDistributionMessage
	signalFfiError := C.signal_sender_key_distribution_message_create(
		&skdm,
		sender.ptr,
		(*[C.SignalUUID_LEN]C.uchar)(unsafe.Pointer(&distributionID)),
		wrapSenderKeyStore(store),
		unsafe.Pointer(&context))
	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}
	return wrapSenderKeyDistributionMessage(skdm), nil
}

func DeserializeSenderKeyDistributionMessage(serialized []byte) (*SenderKeyDistributionMessage, error) {
	var skdm *C.SignalSenderKeyDistributionMessage
	signalFfiError := C.signal_sender_key_distribution_message_deserialize(&skdm, BytesToBuffer(serialized))
	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}
	return wrapSenderKeyDistributionMessage(skdm), nil
}

func (sc *SenderKeyDistributionMessage) Destroy() error {
	runtime.SetFinalizer(sc, nil)
	return wrapError(C.signal_sender_key_distribution_message_destroy(sc.ptr))
}

func (sc *SenderKeyDistributionMessage) Serialize() ([]byte, error) {
	var serialized *C.uchar
	var length C.ulong
	signalFfiError := C.signal_sender_key_distribution_message_serialize(&serialized, &length, sc.ptr)
	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}
	return CopyBufferToBytes(serialized, length), nil
}

func (sc *SenderKeyDistributionMessage) Process(sender *Address, store SenderKeyStore, context StoreContext) error {
	signalFfiError := C.signal_process_sender_key_distribution_message(
		sender.ptr,
		sc.ptr,
		wrapSenderKeyStore(store),
		unsafe.Pointer(&context))
	if signalFfiError != nil {
		return wrapError(signalFfiError)
	}
	return nil
}
