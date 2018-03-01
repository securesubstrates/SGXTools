SGXTools -- Security Tools for Analysizing Intel SGX 

# Installation

## Source fetch

To download code from github, run ``git clone --recursive <github_url>``

The code uses [elf-edit](https://github.com/GaloisInc/elf-edit) haskell package provided by Galois Inc., which is not available on Hackage. The recurisve clone should download this package all by itself, but if it does not then you may need to download it manually. To build the code in cabal sandbox, one needs to run ``cabal sandbox add-source elf-edit``.

To build the code, run ``$ cabal build``
