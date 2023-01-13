package libsignalgo

/*
#cgo LDFLAGS: ./libsignal/target/release/libsignal_ffi.a -ldl
#include "./libsignal/libsignal-ffi.h"
*/
import "C"
import (
	"unsafe"

	gopointer "github.com/mattn/go-pointer"
)

func wrapStoreCallback[T any](storeCtx, ctx unsafe.Pointer, callback func(store T, context StoreContext) error) C.int {
	store := gopointer.Restore(storeCtx).(T)
	var context StoreContext
	if ctx != nil {
		if restored := gopointer.Restore(ctx); restored != nil {
			context = restored.(StoreContext)
		}
	}
	if err := callback(store, context); err != nil {
		return -1
	}
	return 0
}
