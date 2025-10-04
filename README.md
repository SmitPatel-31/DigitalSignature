# Ed25519 Digital Signature CLI

A tiny C++17 command-line tool that demonstrates how to create, sign, and verify Ed25519 digital signatures using OpenSSL's EVP API.

## Core Concepts

- **Digital signature**: A small piece of data generated with a private key that lets anyone validate that a message came from the key holder and was not modified. Verification is done with the matching public key.
- **Ed25519**: A modern elliptic-curve signature scheme that is fast, deterministic, and designed to avoid many common implementation pitfalls.
- **PEM files (`.pem`)**: Text files that wrap binary key material or certificates in a standard Base64 + header/footer format. This project stores keys in PEM so they remain portable and easy to inspect with OpenSSL tools.

## Project Layout

- `digital_signatures.cpp` – CLI source with key generation, signing, and verification helpers.
- `private.pem` / `public.pem` – Example keys created by running `gen-key`.
- `input.txt`, `input2.txt`, `signature.sig` – Sample files for signing and verifying.

## Requirements

- A C++17-capable compiler (Clang or GCC works on macOS/Linux; MSYS2 MinGW on Windows).
- OpenSSL 3.x development libraries.

### macOS (Homebrew)

```bash
brew install openssl@3
export CPPFLAGS="-I$(brew --prefix openssl@3)/include"
export LDFLAGS="-L$(brew --prefix openssl@3)/lib"
```

### Linux (Debian/Ubuntu example)

```bash
sudo apt update && sudo apt install build-essential libssl-dev
```

### Windows (MSYS2 MinGW)

```bash
pacman -S mingw-w64-x86_64-toolchain mingw-w64-x86_64-openssl
```

## Build

From the project root:

```bash
g++ -std=c++17 digital_signatures.cpp -o dsign \
    -I$(brew --prefix openssl@3)/include \
    -L$(brew --prefix openssl@3)/lib -lcrypto
```

Adjust `-I`/`-L` paths to match your platform if you are not on Homebrew. On Linux, the shorter command usually works:

```bash
g++ -std=c++17 digital_signatures.cpp -o dsign -lcrypto
```

## Usage

```
./dsign gen-key <private.pem> <public.pem>
./dsign sign <private.pem> <input_file> <signature.sig>
./dsign verify <public.pem> <input_file> <signature.sig>
```

### Typical Session

```bash
./dsign gen-key private.pem public.pem
./dsign sign private.pem input.txt signature.sig
./dsign verify public.pem input.txt signature.sig  # prints OK when the signature matches
```

- `gen-key` creates a new Ed25519 key pair and writes them to PEM files.
- `sign` reads the input file, produces a signature, and writes the raw signature bytes to the target path.
- `verify` checks the signature against the message and reports success or failure.

## Inspecting PEM Files

Use OpenSSL's command-line tools to peek inside the keys:

```bash
openssl pkey -in private.pem -text
openssl pkey -in public.pem -pubin -text
```

## Troubleshooting

- **`fatal error: 'openssl/evp.h' file not found`** – Ensure the OpenSSL include path is on your compiler command with `-I` and the library path with `-L`. The `CPPFLAGS`/`LDFLAGS` exports above solve this on macOS.
- **Linker errors about `EVP_*` symbols** – Verify you are linking against `-lcrypto` (and `-lssl` if you add TLS-related calls).
- **Corrupted signature files** – Make sure you copy the binary `signature.sig` file without modifying it, and avoid opening/saving it in text editors.

## Next Steps

Feel free to extend the tool with additional key formats, support for detached signature outputs (Base64, hex), or integration with other OpenSSL-supported signature algorithms.
