package libsignalgo

import (
	"fmt"
	"reflect"
)

func sizeMustMatch(a, b int) int {
	if a != b {
		panic("libsignal-ffi type size mismatch")
	}

	return a
}

func ffiTypeSizeMustMatch(ffiValue any, size int) bool {
	ffiType := reflect.ValueOf(ffiValue).Type()

	if ffiType.Len() != size {
		panic(fmt.Sprintf("libsignal-ffi type size mismatch: %s is %d bytes but C def expects %d", ffiType.Name(), ffiType.Len(), size))
	}

	return true
}
