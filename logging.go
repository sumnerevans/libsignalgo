package libsignalgo

/*
#cgo LDFLAGS: ./libsignal/target/release/libsignal_ffi.a -ldl
#include <./libsignal/libsignal-ffi.h>

extern bool signal_log_enabled_callback(char *target, SignalLogLevel level);
extern void signal_log_callback(char *target, SignalLogLevel level, char *file, uint32_t line, char *message);
extern void signal_log_flush_callback();
*/
import "C"

var ffiLogger FFILogger

//export signal_log_enabled_callback
func signal_log_enabled_callback(target *C.char, level C.SignalLogLevel) C.bool {
	return C.bool(ffiLogger.Enabled(C.GoString(target), LogLevel(int(level))))
}

//export signal_log_callback
func signal_log_callback(target *C.char, level C.SignalLogLevel, file *C.char, line C.uint32_t, message *C.char) {
	ffiLogger.Log(C.GoString(target), LogLevel(int(level)), C.GoString(file), int(line), C.GoString(message))
}

//export signal_log_flush_callback
func signal_log_flush_callback() {
	ffiLogger.Flush()
}

type LogLevel int

const (
	LogLevelError LogLevel = iota + 1
	LogLevelWarn
	LogLevelInfo
	LogLevelDebug
	LogLevelTrace
)

type FFILogger struct {
	Enabled func(target string, level LogLevel) bool
	Log     func(target string, level LogLevel, file string, line int, message string)
	Flush   func()
}

func InitLogger(level LogLevel, logger FFILogger) {
	ffiLogger = logger
	C.signal_init_logger(C.SignalLogLevel(level), C.SignalFfiLogger{
		enabled: C.SignalLogEnabledCallback(C.signal_log_enabled_callback),
		log:     C.SignalLogCallback(C.signal_log_callback),
		flush:   C.SignalLogFlushCallback(C.signal_log_flush_callback),
	})
}
