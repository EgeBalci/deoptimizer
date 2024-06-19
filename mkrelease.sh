#!/bin/bash 
## ANSI Colors (FG & BG)
RED="$(printf '\033[31m')" GREEN="$(printf '\033[32m')" YELLOW="$(printf '\033[33m')" BLUE="$(printf '\033[34m')"
MAGENTA="$(printf '\033[35m')" CYAN="$(printf '\033[36m')" WHITE="$(printf '\033[37m')" BLACK="$(printf '\033[30m')"
REDBG="$(printf '\033[41m')" GREENBG="$(printf '\033[42m')" YELLOWBG="$(printf '\033[43m')" BLUEBG="$(printf '\033[44m')"
MAGENTABG="$(printf '\033[45m')" CYANBG="$(printf '\033[46m')" WHITEBG="$(printf '\033[47m')" BLACKBG="$(printf '\033[40m')"
RESET="$(printf '\e[0m')"

## Globals
[[ -n $VERBOSE ]] && ERR_LOG="$(tty)"

print_status() {
    echo "${YELLOW}[*] ${RESET}${1}"
}

print_warning() {
  echo -n "${YELLOW}[!] ${RESET}${1}"
}

print_error() {
  echo "${RED}[-] ${RESET}${1}"
}

print_fatal() {
  echo -e "${RED}[!] $1\n${RESET}"
  kill -10 $$
}

print_good() {
  echo "${GREEN}[+] ${RESET}${1}"
}

print_verbose() {
  if [[ -n "${VERBOSE}" ]]; then
    echo "${WHITE}[*] ${RESET}${1}"
  fi
}

must_exist() {
  for i in "$@"; do
		command -v "$i" >$ERR_LOG || print_fatal "$i not installed! Exiting..."
  done
}


## Handle SININT
exit_on_signal_SIGINT () {
  echo ""
	print_fatal "Script interrupted!"
}

exit_on_signal_SIGTERM () {
	echo ""
  print_fatal "Script interrupted!"
}

trap exit_on_signal_SIGINT SIGINT
trap exit_on_signal_SIGTERM SIGTERM

RELEASE_DIR="$(pwd)/release"
ERR_LOG="/dev/null"

must_exist "grep" "cut" "tar" "sha1sum"

[[ ! -f ./Cargo.toml ]] && print_fatal "Cargo.toml not found!"
VERSION=$(grep "^version = " Cargo.toml|cut -d'"' -f2)

print_status "[$(date --rfc-3339=date)] Packaging new release for version $VERSION" 
mkdir -p "$RELEASE_DIR" &> "$ERR_LOG"

tar czvf "$RELEASE_DIR/deoptimizer_linux_x86_64_v$VERSION.tar.gz"\
  "./target/x86_64-unknown-linux-musl/release/deoptimizer" &> "$ERR_LOG" || print_fatal "Linux x86_64 release failed!"

tar czvf "$RELEASE_DIR/deoptimizer_linux_i686_v$VERSION.tar.gz"\
  "./target/i686-unknown-linux-musl/release/deoptimizer" &> "$ERR_LOG" || print_fatal "Linux i686 release failed!"

tar czvf "$RELEASE_DIR/deoptimizer_linux_aarch64_v$VERSION.tar.gz"\
  "./target/aarch64-unknown-linux-musl/release/deoptimizer" &> "$ERR_LOG" || print_fatal "Linux aarch64 release failed!"

tar czvf "$RELEASE_DIR/deoptimizer_windows_x86_64_v$VERSION.tar.gz"\
  "./target/x86_64-pc-windows-gnu/release/deoptimizer.exe" &> "$ERR_LOG" || print_fatal "Windows x86_64 release failed!"

tar czvf "$RELEASE_DIR/deoptimizer_windows_i686_v$VERSION.tar.gz"\
  "./target/i686-pc-windows-gnu/release/deoptimizer.exe" &> "$ERR_LOG" || print_fatal "Windows i686 release failed!"



print_good "All done!"

cd $RELEASE_DIR
echo -e "\n\`\`\`"
sha1sum *
echo -e "\`\`\`\n"
