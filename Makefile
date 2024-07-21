FLAGS=RUSTFLAGS="-C target-feature=+crt-static"
NIGHTLY_FLAGS=RUSTFLAGS="-C target-feature=+crt-static -Zlocation-detail=none"
BUILD=cargo build --release
CROSS=cross build --release
default:
	${BUILD}
static:
	${FLAGS} ${BUILD} --target x86_64-unknown-linux-musl
nightly:
	${NIGHTLY_FLAGS} ${BUILD}
windows:
	${BUILD} --target x86_64-pc-windows-gnu
	${BUILD} --target i686-pc-windows-gnu
	# ${BUILD} --target aarch64-pc-windows-msvc
linux:
	${FLAGS} ${BUILD} --target x86_64-unknown-linux-musl
	${FLAGS} ${CROSS} --target i686-unknown-linux-musl
	${FLAGS} ${CROSS} --target aarch64-unknown-linux-musl
darwin:
	${BUILD} --target x86_64-apple-darwin
	${BUILD} --target aarch64-apple-darwin


all: linux windows darwin 
