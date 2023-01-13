package libsignalgo

/*
#cgo LDFLAGS: ./libsignal/target/release/libsignal_ffi.a -ldl
#include "./libsignal/libsignal-ffi.h"

typedef const SignalPreKeyRecord const_pre_key_record;

extern int signal_load_pre_key_callback(void *store_ctx, SignalPreKeyRecord **recordp, uint32_t id, void *ctx);
extern int signal_store_pre_key_callback(void *store_ctx, uint32_t id, const_pre_key_record *record, void *ctx);
extern int signal_remove_pre_key_callback(void *store_ctx, uint32_t id, void *ctx);
*/
import "C"
import (
	"unsafe"

	gopointer "github.com/mattn/go-pointer"
)

type PreKeyStore interface {
	LoadPreKey(id uint32, context StoreContext) (*PreKeyRecord, error)
	StorePreKey(id uint32, preKeyRecord *PreKeyRecord, context StoreContext) error
	RemovePreKey(id uint32, context StoreContext) error
}

//export signal_load_pre_key_callback
func signal_load_pre_key_callback(storeCtx unsafe.Pointer, keyp **C.SignalPreKeyRecord, id C.uint32_t, ctx unsafe.Pointer) C.int {
	return wrapStoreCallback(storeCtx, ctx, func(store PreKeyStore, context StoreContext) error {
		key, err := store.LoadPreKey(uint32(id), context)
		if err == nil && key != nil {
			*keyp = key.ptr
		}
		return err
	})
}

//export signal_store_pre_key_callback
func signal_store_pre_key_callback(storeCtx unsafe.Pointer, id C.uint32_t, preKeyRecord *C.const_pre_key_record, ctx unsafe.Pointer) C.int {
	return wrapStoreCallback(storeCtx, ctx, func(store PreKeyStore, context StoreContext) error {
		record := PreKeyRecord{ptr: (*C.SignalPreKeyRecord)(unsafe.Pointer(preKeyRecord))}
		cloned, err := record.Clone()
		if err != nil {
			return err
		}
		return store.StorePreKey(uint32(id), cloned, context)
	})
}

//export signal_remove_pre_key_callback
func signal_remove_pre_key_callback(storeCtx unsafe.Pointer, id C.uint32_t, ctx unsafe.Pointer) C.int {
	return wrapStoreCallback(storeCtx, ctx, func(store PreKeyStore, context StoreContext) error {
		return store.RemovePreKey(uint32(id), context)
	})
}

func wrapPreKeyStore(store PreKeyStore) *C.SignalPreKeyStore {
	// TODO: This is probably a memory leak
	return &C.SignalPreKeyStore{
		ctx:            gopointer.Save(store),
		load_pre_key:   C.SignalLoadPreKey(C.signal_load_pre_key_callback),
		store_pre_key:  C.SignalStorePreKey(C.signal_store_pre_key_callback),
		remove_pre_key: C.SignalRemovePreKey(C.signal_remove_pre_key_callback),
	}
}
