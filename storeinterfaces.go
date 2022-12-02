package libsignalgo

/*
#cgo LDFLAGS: ./libsignal/target/release/libsignal_ffi.a -ldl
#include "./libsignal/libsignal-ffi.h"
*/
import "C"

// type SessionStore[T any] interface {
// 	LoadSession(storeCtx T, record *SessionRecord, address Address, ctx any) (*SessionRecord, error)
// 	StoreSession(storeCtx T, address Address, record *SessionRecord, ctx any)
// }
