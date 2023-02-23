package libsignalgo

/*
#cgo LDFLAGS: ./libsignal/target/release/libsignal_ffi.a -ldl
#include "./libsignal/libsignal-ffi.h"
*/
import "C"

type UuidCiphertext [65]byte

var _ = ffiTypeSizeMustMatch(UuidCiphertext{}, C.SignalUUID_CIPHERTEXT_LEN)
