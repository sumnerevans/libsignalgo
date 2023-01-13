package libsignalgo

/*
#cgo LDFLAGS: ./libsignal/target/release/libsignal_ffi.a -ldl
#include "./libsignal/libsignal-ffi.h"

typedef const SignalProtocolAddress const_address;
typedef const SignalPublicKey const_public_key;

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

type IdentityKeyStore interface {
	GetIdentityKeyPair(context StoreContext) (*PrivateKey, error)
	GetLocalRegistrationId(idp *uint32) error
	SaveIdentityKey(address *Address, publicKey *PublicKey) error
	GetIdentityKey(publicKey **PublicKey, address *Address) error
	IsTrustedIdentity(address *Address, publicKey *PublicKey, direction uint) error
}

//export signal_get_identity_key_pair_callback
func signal_get_identity_key_pair_callback(storeCtx unsafe.Pointer, keyp **C.SignalPrivateKey, ctx unsafe.Pointer) C.int {
	store := gopointer.Restore(storeCtx).(IdentityKeyStore)
	context := gopointer.Restore(ctx).(StoreContext)
	key, err := store.GetIdentityKeyPair(context)
	if err != nil && key != nil {
		*keyp = key.ptr
	}
	return 0
}

//export signal_get_local_registration_id_callback
func signal_get_local_registration_id_callback(storeCtx unsafe.Pointer, idp *C.uint32_t, ctx unsafe.Pointer) C.int {
	panic("not implemented")
}

//export signal_save_identity_key_callback
func signal_save_identity_key_callback(storeCtx unsafe.Pointer, address *C.const_address, public_key *C.const_public_key, ctx unsafe.Pointer) C.int {
	panic("not implemented")
}

//export signal_get_identity_key_callback
func signal_get_identity_key_callback(storeCtx unsafe.Pointer, public_keyp **C.SignalPublicKey, address *C.const_address, ctx unsafe.Pointer) C.int {
	panic("not implemented")
}

//export signal_is_trusted_identity_callback
func signal_is_trusted_identity_callback(storeCtx unsafe.Pointer, address *C.const_address, public_key *C.const_public_key, direction C.uint, ctx unsafe.Pointer) C.int {
	panic("not implemented")
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
