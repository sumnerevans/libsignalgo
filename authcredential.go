package libsignalgo

/*
#cgo LDFLAGS: ./libsignal/target/release/libsignal_ffi.a -ldl
#include "./libsignal/libsignal-ffi.h"
*/
import "C"

type AuthCredential [181]byte

var _ = ffiTypeSizeMustMatch(AuthCredential{}, C.SignalAUTH_CREDENTIAL_LEN)
