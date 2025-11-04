# Ascon Provider for OpenSSL 3.0

An OpenSSL 3.0 provider implementing the [Ascon](https://ascon.iaik.tugraz.at/) family of authenticated encryption and hashing algorithms, designed for lightweight and secure cryptographic operations.

## Features

- **ASCON-128 AEAD**: Fully implemented authenticated encryption with associated data
- **Planned**: ASCON-128a and ASCON-80pq AEAD variants
- **Planned**: ASCON-Hash and ASCON-XOF hash functions

## Requirements

- OpenSSL 3.0 or later
- CMake 3.20 or later
- C compiler with C99 support
- Git (for submodules)

## Building

### Clone the Repository

```bash
git clone --recursive <repository-url>
cd Ascon-Provider
```

If you've already cloned without `--recursive`, initialize submodules:

```bash
git submodule update --init --recursive
```

### Build the Provider

```bash
mkdir build
cd build
cmake ..
make
```

The provider module (`akif_ascon.so` on Linux, `akif_ascon.dll` on Windows) will be built in the `build` directory.

### Testing

Run the test suite using CTest:

```bash
cd build
ctest
```

Or run individual tests:

```bash
cd build
OPENSSL_MODULES=$(pwd) ./test_akif_ascon
```

**Note**: When running tests manually, you must set the `OPENSSL_MODULES` environment variable to point to the directory containing `akif_ascon.so`.

## License

See [LICENSE.md](LICENSE.md) for details.

## References

- [Ascon Algorithm Family](https://ascon.iaik.tugraz.at/)
- [OpenSSL Provider Documentation](https://www.openssl.org/docs/man3.0/man7/provider.html)
- [LibAscon Library](https://github.com/TheMatjaz/LibAscon)

## Authors

- Initial implementation by: @theakifmehmood, @romen
- Co-authored by: @evil-cry Dominic Cunningham
- Co-authored by: @Jcb5272 Jack Barsa
- Co-authored by: Max Deng
