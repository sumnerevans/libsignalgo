package libsignalgo

/*
#cgo LDFLAGS: ./libsignal/target/release/libsignal_ffi.a -ldl
#include "./libsignal/libsignal-ffi.h"

typedef const SignalSignedPreKeyRecord const_signed_pre_key_record;

extern int signal_load_signed_pre_key_callback(void *store_ctx, SignalSignedPreKeyRecord **recordp, uint32_t id, void *ctx);
extern int signal_store_signed_pre_key_callback(void *store_ctx, uint32_t id, const_signed_pre_key_record *record, void *ctx);
*/
import "C"
import (
	"unsafe"

	gopointer "github.com/mattn/go-pointer"
)

type SignedPreKeyStore interface {
	LoadSignedPreKey(id uint32, context StoreContext) (*SignedPreKeyRecord, error)
	StoreSignedPreKey(id uint32, signedPreKeyRecord *SignedPreKeyRecord, context StoreContext) error
}

//export signal_load_signed_pre_key_callback
func signal_load_signed_pre_key_callback(storeCtx unsafe.Pointer, keyp **C.SignalSignedPreKeyRecord, id C.uint32_t, ctx unsafe.Pointer) C.int {
	return wrapStoreCallback(storeCtx, ctx, func(store SignedPreKeyStore, context StoreContext) error {
		key, err := store.LoadSignedPreKey(uint32(id), context)
		if err == nil && key != nil {
			*keyp = key.ptr
		}
		return err
	})
}

//export signal_store_signed_pre_key_callback
func signal_store_signed_pre_key_callback(storeCtx unsafe.Pointer, id C.uint32_t, preKeyRecord *C.const_signed_pre_key_record, ctx unsafe.Pointer) C.int {
	return wrapStoreCallback(storeCtx, ctx, func(store SignedPreKeyStore, context StoreContext) error {
		record := SignedPreKeyRecord{ptr: (*C.SignalSignedPreKeyRecord)(unsafe.Pointer(preKeyRecord))}
		cloned, err := record.Clone()
		if err != nil {
			return err
		}
		return store.StoreSignedPreKey(uint32(id), cloned, context)
	})
}

func wrapSignedPreKeyStore(store SignedPreKeyStore) *C.SignalSignedPreKeyStore {
	// TODO: This is probably a memory leak
	return &C.SignalSignedPreKeyStore{
		ctx:                  gopointer.Save(store),
		load_signed_pre_key:  C.SignalLoadSignedPreKey(C.signal_load_signed_pre_key_callback),
		store_signed_pre_key: C.SignalStoreSignedPreKey(C.signal_store_signed_pre_key_callback),
	}
}
