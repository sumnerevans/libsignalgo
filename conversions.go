package libsignalgo

/*
#cgo LDFLAGS: ./libsignal/target/release/libsignal_ffi.a -ldl
#include "./libsignal/libsignal-ffi.h"
*/
import "C"

func CopyCStringToString(cString *C.char) (s string) {
	s = C.GoString(cString)
	C.signal_free_string(cString)
	return
}
