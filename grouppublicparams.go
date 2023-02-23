package libsignalgo

/*
#cgo LDFLAGS: ./libsignal/target/release/libsignal_ffi.a -ldl
#include "./libsignal/libsignal-ffi.h"
*/
import "C"

type GroupPublicParams [97]byte

var _ = ffiTypeSizeMustMatch(GroupPublicParams{}, C.SignalGROUP_PUBLIC_PARAMS_LEN)
