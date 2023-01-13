package libsignalgo

/*
#cgo LDFLAGS: ./libsignal/target/release/libsignal_ffi.a -ldl
#include "./libsignal/libsignal-ffi.h"
*/
import "C"

type ServerPublicParams [417]byte

var _ = ffiTypeSizeMustMatch(ServerPublicParams{}, C.SignalSERVER_PUBLIC_PARAMS_LEN)

func NewServerPublicParams(contents [C.SignalSERVER_PUBLIC_PARAMS_LEN]byte) (ServerPublicParams, error) {
	signalFfiError := C.signal_server_public_params_check_valid_contents(BytesToBuffer(contents[:]))
	if signalFfiError != nil {
		return ServerPublicParams{}, wrapError(signalFfiError)
	}

	return ServerPublicParams(contents), nil
}
