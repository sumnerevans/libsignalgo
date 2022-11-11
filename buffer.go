package libsignalgo

/*
#cgo LDFLAGS: ./libsignal/target/release/libsignal_ffi.a -ldl
#include "./libsignal/libsignal-ffi.h"
*/
import "C"

func BytesToBuffer(data []byte) C.SignalBorrowedBuffer {
	return C.SignalBorrowedBuffer{
		base:   (*C.uchar)(&data[0]),
		length: C.uintptr_t(len(data)),
	}
}
