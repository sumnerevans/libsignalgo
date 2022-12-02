package libsignalgo

/*
#cgo LDFLAGS: ./libsignal/target/release/libsignal_ffi.a -ldl
#include "./libsignal/libsignal-ffi.h"

typedef const SignalSessionRecord const_record;
typedef const SignalProtocolAddress const_address;
typedef const SignalPublicKey const_public_key;

extern int signal_load_session_callback(void *store_ctx, SignalSessionRecord **recordp, const_address *address, void *ctx);
extern int signal_store_session_callback(void *store_ctx, const_address *address, const_record *record, void *ctx);

extern int signal_get_identity_key_pair_callback(void *store_ctx, SignalPrivateKey **keyp, void *ctx);
extern int signal_get_local_registration_id_callback(void *store_ctx, uint32_t *idp, void *ctx);
extern int signal_save_identity_key_callback(void *store_ctx, const_address *address, const_public_key *public_key, void *ctx);
extern int signal_get_identity_key_callback(void *store_ctx, SignalPublicKey **public_keyp, const_address *address, void *ctx);
extern int signal_is_trusted_identity_callback(void *store_ctx, const_address *address, const_public_key *public_key, unsigned int direction, void *ctx);
*/
import "C"
import (
	"unsafe"

	gopointer "github.com/mattn/go-pointer"
)

//export signal_load_session_callback
func signal_load_session_callback(storeCtx unsafe.Pointer, recordp **C.SignalSessionRecord, address *C.const_address, ctx unsafe.Pointer) C.int {
	store := gopointer.Restore(storeCtx).(SessionStore)
	context := gopointer.Restore(ctx).(*StoreContext)
	record, err := store.LoadSession(
		Address{ptr: (*C.SignalProtocolAddress)(unsafe.Pointer(address))},
		context,
	)
	if err == nil {
		recordp = &record.ptr
	} else {
		recordp = nil
	}
	return 0
}

//export signal_store_session_callback
func signal_store_session_callback(storeCtx unsafe.Pointer, address *C.const_address, record *C.const_record, ctx unsafe.Pointer) C.int {
	store := gopointer.Restore(storeCtx).(SessionStore)
	context := gopointer.Restore(ctx).(*StoreContext)
	err := store.StoreSession(
		Address{ptr: (*C.SignalProtocolAddress)(unsafe.Pointer(address))},
		&SessionRecord{ptr: (*C.SignalSessionRecord)(unsafe.Pointer(record))},
		context,
	)
	if err != nil {
		return -1
	}
	return 0
}

type StoreContext struct{}

type SessionStore interface {
	LoadSession(address Address, context *StoreContext) (*SessionRecord, error)
	StoreSession(address Address, record *SessionRecord, context *StoreContext) error
}

func wrapSessionStore(store SessionStore) *C.SignalSessionStore {
	return &C.SignalSessionStore{
		ctx:           gopointer.Save(store),
		load_session:  C.SignalLoadSession(C.signal_load_session_callback),
		store_session: C.SignalStoreSession(C.signal_store_session_callback),
	}
}

//export signal_get_identity_key_pair_callback
func signal_get_identity_key_pair_callback(storeCtx unsafe.Pointer, keyp **C.SignalPrivateKey, ctx unsafe.Pointer) C.int {
	return 0
}

//export signal_get_local_registration_id_callback
func signal_get_local_registration_id_callback(storeCtx unsafe.Pointer, idp *C.uint32_t, ctx unsafe.Pointer) C.int {
	return 0
}

//export signal_save_identity_key_callback
func signal_save_identity_key_callback(storeCtx unsafe.Pointer, address *C.const_address, public_key *C.const_public_key, ctx unsafe.Pointer) C.int {
	return 0
}

//export signal_get_identity_key_callback
func signal_get_identity_key_callback(storeCtx unsafe.Pointer, public_keyp **C.SignalPublicKey, address *C.const_address, ctx unsafe.Pointer) C.int {
	return 0
}

//export signal_is_trusted_identity_callback
func signal_is_trusted_identity_callback(storeCtx unsafe.Pointer, address *C.const_address, public_key *C.const_public_key, direction C.uint, ctx unsafe.Pointer) C.int {
	return 0
}

type IdentityKeyStore interface {
	GetIdentityKeyPair(privateKey **PrivateKey) error
	GetLocalRegistrationId(idp *uint32) error
	SaveIdentityKey(address *Address, publicKey *PublicKey) error
	GetIdentityKey(publicKey **PublicKey, address *Address) error
	IsTrustedIdentity(address *Address, publicKey *PublicKey, direction uint) error
}

func wrapIdentityKeyStore(store IdentityKeyStore) *C.SignalIdentityKeyStore {
	return &C.SignalIdentityKeyStore{
		ctx:                       gopointer.Save(store),
		get_identity_key_pair:     C.SignalGetIdentityKeyPair(C.signal_get_identity_key_pair_callback),
		get_local_registration_id: C.SignalGetLocalRegistrationId(C.signal_get_local_registration_id_callback),
		save_identity:             C.SignalSaveIdentityKey(C.signal_save_identity_key_callback),
		get_identity:              C.SignalGetIdentityKey(C.signal_get_identity_key_callback),
		is_trusted_identity:       C.SignalIsTrustedIdentity(C.signal_is_trusted_identity_callback),
	}
}
