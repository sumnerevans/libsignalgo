package libsignalgo

/*
#cgo LDFLAGS: ./libsignal/target/release/libsignal_ffi.a -ldl
#include "./libsignal/libsignal-ffi.h"
*/
import "C"
import (
	"runtime"
	"unsafe"
)

type SealedSenderAddress struct {
	E164     string
	UUID     string
	DeviceID uint32
}

type UnidentifiedSenderMessageContentHint uint32

const (
	UnidentifiedSenderMessageContentHintDefault    UnidentifiedSenderMessageContentHint = 0
	UnidentifiedSenderMessageContentHintResendable UnidentifiedSenderMessageContentHint = 1
	UnidentifiedSenderMessageContentHintImplicit   UnidentifiedSenderMessageContentHint = 2
)

type UnidentifiedSenderMessageContent struct {
	ptr *C.SignalUnidentifiedSenderMessageContent
}

func wrapUnidentifiedSenderMessageContent(ptr *C.SignalUnidentifiedSenderMessageContent) *UnidentifiedSenderMessageContent {
	messageContent := &UnidentifiedSenderMessageContent{ptr: ptr}
	runtime.SetFinalizer(messageContent, (*UnidentifiedSenderMessageContent).Destroy)
	return messageContent
}

func NewUnidentifiedSenderMessageContent(message *CiphertextMessage, senderCertificate *SenderCertificate, contentHint UnidentifiedSenderMessageContentHint, groupID []byte) (*UnidentifiedSenderMessageContent, error) {
	var usmc *C.SignalUnidentifiedSenderMessageContent
	signalFfiError := C.signal_unidentified_sender_message_content_new(&usmc, message.ptr, senderCertificate.ptr, C.uint32_t(contentHint), BytesToBuffer(groupID))
	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}
	return wrapUnidentifiedSenderMessageContent(usmc), nil
}

func DeserializeUnidentifiedSenderMessageContent(serialized []byte) (*UnidentifiedSenderMessageContent, error) {
	var usmc *C.SignalUnidentifiedSenderMessageContent
	signalFfiError := C.signal_unidentified_sender_message_content_deserialize(&usmc, BytesToBuffer(serialized))
	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}
	return wrapUnidentifiedSenderMessageContent(usmc), nil
}

func (usmc *UnidentifiedSenderMessageContent) Destroy() error {
	runtime.SetFinalizer(usmc, nil)
	signalFfiError := C.signal_unidentified_sender_message_content_destroy(usmc.ptr)
	if signalFfiError != nil {
		return wrapError(signalFfiError)
	}
	return nil
}

func (usmc *UnidentifiedSenderMessageContent) Serialize() ([]byte, error) {
	var serialized *C.uchar
	var length C.ulong
	signalFfiError := C.signal_unidentified_sender_message_content_serialize(&serialized, &length, usmc.ptr)
	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}
	return C.GoBytes(unsafe.Pointer(serialized), C.int(length)), nil
}

func (usmc *UnidentifiedSenderMessageContent) GetContents() ([]byte, error) {
	var contents *C.uchar
	var length C.ulong
	signalFfiError := C.signal_unidentified_sender_message_content_get_contents(&contents, &length, usmc.ptr)
	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}
	return C.GoBytes(unsafe.Pointer(contents), C.int(length)), nil
}

func (usmc *UnidentifiedSenderMessageContent) GetGroupID() ([]byte, error) {
	var groupID *C.uchar
	var length C.ulong
	signalFfiError := C.signal_unidentified_sender_message_content_get_group_id(&groupID, &length, usmc.ptr)
	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}
	return C.GoBytes(unsafe.Pointer(groupID), C.int(length)), nil
}

func (usmc *UnidentifiedSenderMessageContent) GetSenderCertificate() (*SenderCertificate, error) {
	var senderCertificate *C.SignalSenderCertificate
	signalFfiError := C.signal_unidentified_sender_message_content_get_sender_cert(&senderCertificate, usmc.ptr)
	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}
	return wrapSenderCertificate(senderCertificate), nil
}

func (usmc *UnidentifiedSenderMessageContent) GetMessageType() (CiphertextMessageType, error) {
	var messageType C.uint8_t
	signalFfiError := C.signal_unidentified_sender_message_content_get_msg_type(&messageType, usmc.ptr)
	if signalFfiError != nil {
		return 0, wrapError(signalFfiError)
	}
	return CiphertextMessageType(messageType), nil
}

func (usmc *UnidentifiedSenderMessageContent) GetContentHint() (UnidentifiedSenderMessageContentHint, error) {
	var contentHint C.uint32_t
	signalFfiError := C.signal_unidentified_sender_message_content_get_content_hint(&contentHint, usmc.ptr)
	if signalFfiError != nil {
		return 0, wrapError(signalFfiError)
	}
	return UnidentifiedSenderMessageContentHint(contentHint), nil
}
