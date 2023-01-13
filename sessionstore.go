package libsignalgo

/*
#cgo LDFLAGS: ./libsignal/target/release/libsignal_ffi.a -ldl
#include "./libsignal/libsignal-ffi.h"

typedef const SignalSessionRecord const_session_record;
typedef const SignalProtocolAddress const_address;

extern int signal_load_session_callback(void *store_ctx, SignalSessionRecord **recordp, const_address *address, void *ctx);
extern int signal_store_session_callback(void *store_ctx, const_address *address, const_session_record *record, void *ctx);
*/
import "C"
import (
	"unsafe"

	gopointer "github.com/mattn/go-pointer"
)

type StoreContext interface{}

type SessionStore interface {
	LoadSession(address *Address, context StoreContext) (*SessionRecord, error)
	StoreSession(address *Address, record *SessionRecord, context StoreContext) error
}

//export signal_load_session_callback
func signal_load_session_callback(storeCtx unsafe.Pointer, recordp **C.SignalSessionRecord, address *C.const_address, ctx unsafe.Pointer) C.int {
	return wrapStoreCallback(storeCtx, ctx, func(store SessionStore, context StoreContext) error {
		record, err := store.LoadSession(
			&Address{ptr: (*C.SignalProtocolAddress)(unsafe.Pointer(address))},
			context,
		)
		if err == nil && record != nil {
			*recordp = record.ptr
		}
		return err
	})
}

//export signal_store_session_callback
func signal_store_session_callback(storeCtx unsafe.Pointer, address *C.const_address, record *C.const_session_record, ctx unsafe.Pointer) C.int {
	return wrapStoreCallback(storeCtx, ctx, func(store SessionStore, context StoreContext) error {
		return store.StoreSession(
			&Address{ptr: (*C.SignalProtocolAddress)(unsafe.Pointer(address))},
			&SessionRecord{ptr: (*C.SignalSessionRecord)(unsafe.Pointer(record))},
			context,
		)
	})
}

func wrapSessionStore(store SessionStore) *C.SignalSessionStore {
	return &C.SignalSessionStore{
		ctx:           gopointer.Save(store),
		load_session:  C.SignalLoadSession(C.signal_load_session_callback),
		store_session: C.SignalStoreSession(C.signal_store_session_callback),
	}
}
