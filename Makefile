all: libsignal/libsignal-ffi.h

libsignal/Cargo.toml:
	git clone https://github.com/signalapp/libsignal.git

libsignal/libsignal-ffi.h: libsignal/target/x86_64-unknown-linux-gnu/release/libsignal_ffi.a
	cd libsignal && cbindgen --profile release rust/bridge/ffi -o libsignal-ffi.h

libsignal/target/x86_64-unknown-linux-gnu/release/libsignal_ffi.a: libsignal/Cargo.toml
	cd libsignal && cargo build --release --verbose
