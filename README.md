SGXTools -- Security Tools for Analysizing Intel SGX

# Introdction

sgxTools is a set of utilities for exploring SGX enclave and
working with remote attestation.

# Installation

## Source fetch

To download code from github, run ``git clone --recursive
<github_url>``

The code uses a modified version of
[elf-edit](https://github.com/axelexic/elf-edit) haskell
package that has been forked from Galois Inc. repo. The
recurisve clone should download this package all by itself,
but if it does not then you may need to download it
manually. To build the code in cabal sandbox, one needs to
run ``cabal sandbox add-source elf-edit``.

To build the code, run ``$ cabal build``
