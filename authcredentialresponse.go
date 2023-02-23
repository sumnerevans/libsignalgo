package libsignalgo

/*
#cgo LDFLAGS: ./libsignal/target/release/libsignal_ffi.a -ldl
#include "./libsignal/libsignal-ffi.h"
*/
import "C"

type AuthCredentialResponse [361]byte

var _ = ffiTypeSizeMustMatch(AuthCredentialResponse{}, C.SignalAUTH_CREDENTIAL_RESPONSE_LEN)
