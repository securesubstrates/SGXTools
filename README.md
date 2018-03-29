SGXTools -- Security Tools for Analyzing Intel SGX

# Introduction

sgxTools is a set of utilities for exploring SGX enclave and
remote attestation.

# Installation

## Source fetch

To download code from github, run ``git clone --recursive
<github_url>``

The code uses a modified version of
[elf-edit](https://github.com/axelexic/elf-edit) forked from
Galois Inc. repo. The recurisve clone should download this
package all by itself, but if it does not then you may need
to download it manually. To build the code in cabal sandbox,
one needs to run ``cabal sandbox add-source elf-edit``.

To build the code, run ``$ cabal build``

# Usage

The sgxTools executable currently supports two main
commands: One to re-measure the enclave, and one to print
the layout of the enclave. The commands are the following:

```
$ ./dist/build/sgxTools/sgxTools -h
sgxTools -- Bundle of SGX Tools

Usage: sgxTools COMMAND
  Tools for working with SGX data structures

  Available options:
    -h,--help                Show this help text

  Available commands:
  metaInfo                 Display enclave metadata layout
  sigStruct                Display contents of a CSS File
  whitelist                Display Whitelist Information
  measure                  Recompute mrenclave
  einitInfo                Display EINIT token information
  hexdump                  Convert binary file to hex
  version                  Display Program Version

```

## measure

Measure re-computes the MRENCLAVE based on the layout given
in the enclave. This is useful for independently computing
the MRENCLAVE without using Intel provided tools.

```
$ ./dist/build/sgxTools/sgxTools measure -h
Invalid option `-h'

Did you mean this?
    -i

Usage: sgxTools measure (-i|--enclave ENCLAVE .SO FILENAME)
  Recompute mrenclave
```

Sample ouput of recomputing the enclave's hash

```
$ ./dist/build/sgxTools/sgxTools measure -i /opt/intel/sgxpsw/aesm/libsgx_le.signed.so
MRENCLAVE : 0x8b659cf36fbd3b8a9077fefd64bfddf61ba391101db525bd1159ab5324c3dc9c

```

## metaInfo

Each Intel Signed Enclave has an ELF Note that contains
information about the layout of the enclave in memory. This
command prints various information about the enclave layout
in memory.

```
$ ./dist/build/sgxTools/sgxTools metaInfo -h
Invalid option -h

Did you mean one of these?
    -i
    -l
    -p
    -c

Usage: sgxTools metaInfo (-i|--enclave ENCLAVE .SO FILENAME) [-l|--print-layout]
                         [-p|--print-patch] [-c|--nocolor]
  Display enclave metadata layout

```

Sample enclave metadata information is listed below. The
``sgx_sign`` tool adds information in the ``sgx_metadata``
note section in the .so file that contains the SGX SigStruct
information. In addition, the metadata section contains
additional information about enclave's memory layout (i.e.,
at what address the stack, the heap, the thread control
structure and any other information that's needed to create
a fully functioning layout). For some strange reason the
``sgx_sign`` tool also patches some information in the
elf-file at run-time before loading it. This information is
also kept in the enclave file.

All these details are showed using the ``metaInfo`` command.

```
$ ./dist/build/sgxTools/sgxTools metaInfo -i /opt/intel/sgxpsw/aesm/libsgx_le.signed.so -l -p
{
  Magic               : 0x86a80294635d0e4c
  Version             : 0x200000002
  Metadata Size       : 3904
  Thread Binding      : TCS_POLICY_UNBIND
  SSA Frame Size      : 1
  Max Save Buffer     : 2632
  Desired MISC Select : 0
  Minimum Thread Pool : 0
  Enclave Size        : 2097152
  Enclave Attributes  :
    {
      DEBUG         : False
      MODE64        : True
      PROVISION_KEY : False
      LAUNCH_KEY    : True
      XFRM          :
        {
          XFRM Enabled    : True
          XCR0            : 7
          XSAVE available : True

        }

    }
  SigStruct           :
    {
      Vendor           : Intel
      Build Date       : 22-Jan-2018
      Product ID       : 32
      Software Version : 1
      MrEnclave        : 0x8b659cf36fbd3b8a9077fefd64bfddf61ba391101db525bd1159ab5324c3dc9c
      MrSigner         : 0x494a7e7138d5985fe6c8b126c7914718f895b6622f04eef8ae8fd2d3d332c6d4
      Misc Select      : MiscSelect {miscExInfo = False, miscReserved_bit1_32 = 0}
      Misc Mask        : MiscSelect {miscExInfo = True, miscReserved_bit1_32 = 0}
      Attributes       :
        {
          DEBUG         : False
          MODE64        : True
          PROVISION_KEY : False
          LAUNCH_KEY    : True
          XFRM          :
            {
              XFRM Enabled    : True
              XCR0            : 3
              XSAVE available : False

            }

        }
      RSA exponent     : 3
      RSA Modulus      : 0xe2288c78828aedfd8cf4a710ba38292719b22697b512fb50d50ad5aaecb537209ecbcd8a3318d83667879f4e49147a5f7a578f7b9e4c8f6de78c7e2cce0de2f14efc4cabf98f1279b92a40536fb1cfb8c6d2b6a18dcfd78be54ca646f62fa5377a952f4ef9605b881950d1402cc96a2d5b0d08c31a09c185d27d7ea4dc49676741e63d6a338396cfc45b82d28a27f5f9f86f1915b13dd4e809d68fcdb240010dbcbeef6db8a49271da39b56fdd456c1c4641164972f00aa1614500c6f76291982e01e7adf5c42bf4a7109ab2e727aa86f497f330d2f9f9e4aee84772a95269256f0b1d229c7569158268a70a3f1e7c036737dddc2d8c2a546efb71773053ffad23805fc0e2013b8911e14e4bdb6c51f42a85693c7f6b2832b6aac44c9c7655d766cc528b22643f52c413066ff37d0ae5589683c3c747ebfe36f38cdee756f52dcbd9ecd2203f95b62eb289d1d6765c581e77cd28c691f61bb785c837c4025c53cc70da2051391097d8a2b3c541573801e0e9c8efa4cd3c0eeb3257d5477a67ff
      RSA Signature    : 0x7e537aae32c4273a6a5695d7e01e6b96f4f58d0338d158ddf577dec0dd8aab648a6862f4208fc9cd19b7f3a8331b6d0eb6e21ee3798c8be12d35f697ca0ede1b15c0f88f86e0fe8c6cd16f4168ddb22344e43c24ec4211db65d426295cdaea70348d92592042be756fc89ac8311e898a010a48c424999ec4934b9a5e029c3211e51a949cdc2b73680cba5e9d9c2fb2dc08cd9073eceb3494d6e4b514d19e14f55f1f3575fb82e823a8f0b14d71bc9bc1f517a54df5c343b619867177cfc3bacdcdd16fce42e54fc1e339df649ca47dfb78d3fb3d20c5367132c4afc27836f15487434723ae4ddf7122f92f36ace3d92f6a8d58a897682ff11b6a43afbcd12227a70c9951cbe63768eaf86739d6287e0d828c00b972b5d1d222de3da4987212d53d22d5b675d6b54bcaa4889e174e2b455d52896c273463d1c8f0998f36302aa250afd7aa430a65c3471fe189604f8f193496d795d354c7acf59753edd73d5493bf695b946f0537752d0a5ca7a98eb5af93be0628888d8482e1c7f9cef282a830
      RSA Q1           : 0x468ffa1383e57be9c26cd506a0fc954862bc9ad48117d08053ab347e732a51297db4d234c64fa2994bf257732fb602289cd66b3abb985b8fac6aa63b2b20da92bcb84c6c349876702866c6e04eefffde9b723e4abdc5f738ecc709d57d64bbe765f26ba72064d3a2e27e9e2afece0e89d0a94b9a554ee3850a58adc265c685fea30c2066f1f7fd15282f07ebabbbf2790f873e39e26e5e51eafc113789263afb6112c5ff9bc21f53a7fc9508fa4d833456a9e6a3db6788ea8c54eb6cbb3127f7133bbfb4222a54798aff4fca64c968c3c5758b432de51a513b8ff95a8f7caa224e6f2723a22e9b807998f83e5790e5669e723e9d5bfbbdae0032f319663bf418ca1e928d63f1c1c1acc1d50ef37aa5ab97cbabd4d04f8b4376c91de92c1911b994a6091a76183111afb9c874dfafd2e8f71ce4bbab1e75ba6b49756b462a7e5544c61582c28c86fef8c5490a7d004889aa3386dec5f5274328a489f28daa0825410d5b16642d820803a091a29f01dca146643401aa7dc3a7bcc54efe90065e5c
      RSA Q2           : 0x244d0b52ac7a80756551b8bdef11347ad22d558d7e1c7025764ac881b4354a37edb6bd30aff46489562667f36f895202ccf44e1f1db54f2a0f6c53ef7fa2a8f9a412ffdd66931d7953940c5c1e3668787e11ba8ef93786fc00e1ea986c361a929627c8855d99ad92e3b3138c2721e85ce1c9a6f929dc3a0f1c1cbd605d75be9bcfd8c85c87f5fe1762225563c93418871087faad09bea7f29893d3055bc5a4a9c7a73fb4494e27fb7dabe297fda69731798a6619aec08e28563248aafb85615e22a95489ded665215fb46878b223b7aa2d4e68f609ff1f1cc3889497ba4dae43d522f243da8c3fe1016ca93e19d83fcb89cb1f568f7d10453638c9cd495b78b541f3380d7ab209c65916b4fd28909e63cedb4c5275b031bc990785549d21a406c065c0fa9681f710b91d027dfddc83744a0a5fc2471b14d8f1d295e869b4844df06473bce9280b7d73a615a231d00f40cb35483f3d6c3d1a69774bb80e45573f8d14c05fac8f2a6483b7d7d610207350f52adc0a6cbe6e8e40b2c5cb7f20d445

    }
  Layout              :
    [{
      Layout ID    : LAYOUT_ID_HEAP_MIN
      Layout Ops   : [E_ADD]
      Layout RVA   : 0xc0000
      Page Count   : 32
      Content Size : 0
      Content Off  : 0
      Content      : ""
      Permissions  : [SI_FLAG_REG
                     ,SI_FLAG_W
                     ,SI_FLAG_R]

    }
    ,{
      Layout ID    : LAYOUT_ID_GUARD
      Layout Ops   : []
      Layout RVA   : 0xe0000
      Page Count   : 16
      Content Size : 0
      Content Off  : 0
      Content      : ""
      Permissions  : []

    }
    ,{
      Layout ID    : LAYOUT_ID_STACK_MAX
      Layout Ops   : [E_GROWDOWN,E_EXTEND,E_ADD]
      Layout RVA   : 0xf0000
      Page Count   : 1
      Content Size : 3435973836
      Content Off  : 0
      Content      : ""
      Permissions  : [SI_FLAG_REG
                     ,SI_FLAG_W
                     ,SI_FLAG_R]

    }
    ,{
      Layout ID    : LAYOUT_ID_STACK_MIN
      Layout Ops   : [E_EXTEND,E_ADD]
      Layout RVA   : 0xf1000
      Page Count   : 1
      Content Size : 3435973836
      Content Off  : 0
      Content      : ""
      Permissions  : [SI_FLAG_REG
                     ,SI_FLAG_W
                     ,SI_FLAG_R]

    }
    ,{
      Layout ID    : LAYOUT_ID_GUARD
      Layout Ops   : []
      Layout RVA   : 0xf2000
      Page Count   : 16
      Content Size : 0
      Content Off  : 0
      Content      : ""
      Permissions  : []

    }
    ,{
      Layout ID    : LAYOUT_ID_TCS
      Layout Ops   : [E_EXTEND,E_ADD]
      Layout RVA   : 0x102000
      Page Count   : 1
      Content Size : 72
      Content Off  : 1888
      Content      : "0000000000000000000000000000000000100000000000000000000002000000913c000000000000000000000000000000300100000000000030010000000000ffffffffffffffff"
      Permissions  : [SI_FLAG_TCS]

    }
    ,{
      Layout ID    : LAYOUT_ID_SSA
      Layout Ops   : [E_EXTEND,E_ADD]
      Layout RVA   : 0x103000
      Page Count   : 2
      Content Size : 0
      Content Off  : 0
      Content      : ""
      Permissions  : [SI_FLAG_REG
                     ,SI_FLAG_W
                     ,SI_FLAG_R]

    }
    ,{
      Layout ID    : LAYOUT_ID_GUARD
      Layout Ops   : []
      Layout RVA   : 0x105000
      Page Count   : 16
      Content Size : 0
      Content Off  : 0
      Content      : ""
      Permissions  : []

    }
    ,{
      Layout ID    : LAYOUT_ID_TD
      Layout Ops   : [E_EXTEND,E_ADD]
      Layout RVA   : 0x115000
      Page Count   : 1
      Content Size : 0
      Content Off  : 0
      Content      : ""
      Permissions  : [SI_FLAG_REG
                     ,SI_FLAG_W
                     ,SI_FLAG_R]

    }
    ,{
      Layout ID    : LAYOUT_ID_GUARD
      Layout Ops   : []
      Layout RVA   : 0x116000
      Page Count   : 234
      Content Size : 0
      Content Off  : 0
      Content      : ""
      Permissions  : []

    }]
  Patches             :
    [{
      Dest    : 0xad040
      Source  : 0x7a8
      Size    : 1488
      Content : "000020000000000000000c00000000000000020000000000010000000000000000300100000000000000ffffffffffff0000ffffffffffff00e0feffffffffff481f0000000000000000000000000000000000000000000040030000000000000000000000000000000000000000000000300100000000005030010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100000000000000000000002000000913c000000000000000000000000000000300100000000000030010000000000ffffffffffffffff0a00000000000000010001002000000000000c0000000000000000000000000003020000000000000a0000001000000000000e000000000000000000000000000000000000000000070043000100000000000f0000000000cccccccc000000000302000000000000080003000100000000100f0000000000cccccccc0000000003020000000000000a0000001000000000200f000000000000000000000000000000000000000000040003000100000000201000000000004800000060070000000100000000000006000300020000000030100000000000000000000000000003020000000000000a0000001000000000501000000000000000000000000000000000000000000005000300010000000050110000000000000000000000000003020000000000000a000000ea0000000060110000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"

    }
    ,{
      Dest    : 0x3c
      Source  : 0xd78
      Size    : 2
      Content : "0000"

    }
    ,{
      Dest    : 0x28
      Source  : 0xd78
      Size    : 8
      Content : "0000000000000000"

    }
    ,{
      Dest    : 0x3e
      Source  : 0xd78
      Size    : 2
      Content : "0000"

    }]

}
```

# whitelist

The Launch Enclave provides access control for which
enclaves are authorized to run on the platform. The list of
authorized MRSIGNERS are stored at
``/var/opt/aesmd/data/white_list_cert.bin`` on Ubuntu. The
``whitelist`` command prints the contents of the Intel
Provided Whitelist along with the public-keys needed for
validating the whitelist. (Note: The LE Root Pubkey is
hardcoded into intel's Launch Enclave and acts as the root
of trust for validating Intel Signed Whitelists.)

```
$ sudo ./dist/build/sgxTools/sgxTools whitelist -i /var/opt/aesmd/data/white_list_cert.bin
{
  LE Root Pubkey (NIST-P256) : (0xa9365c4531676d18c2169c60751c0cee8c5fc98fc891173cebd686cb9b1e3929
                               ,0xb67e11ca81cf287a24444fc98499055e93cce2fee65497ede4da22e10d83095f)
  Intel Whitelist Provider   : {
    Format Version         : 1 (0x1)
    Signer Type            : 0 (0x0)
    Provider ID            : 0 (0x0)
    Root ID                : 0 (0x0)
    Public Key (NIST-P256) : (0x6588088392e73d049df6ced6f2e6963145e189c003fb3a74870b20d32aa8a4a1
                             ,0x32cf58636a63afd64bf95c6077069b628c3975b60d12e55ad33d9b995990ca6d)
    Signature (ECDSA)      : (0xb3282271d31ed17528a6ed892f7ae73a5ca1e1bdd1c9fce9a0d39d59c70157e2
                             ,0x8c9681985e1e6d79eb00684b206beb8a2fa2c44520d5a8df3e8e1f2e8f9298b6)

  }
  Intel Signed Whitelist     : {
    Version         : 1 (0x1)
    Type            : 1 (0x1)
    Provider ID     : 0 (0x0)
    LE Product ID   : 32 (0x20)
    Signer Version  : 30 (0x1e)
    Valid MRSIGNERS : [ec15b10787d2f84667ceb0b598ffc44a1f1cb80f670aae5df9e8fa9f6376e1f8
                      ,4be2af036366ebc4176e70a539f00445d9057d9604f8ead3e323f3804a11f9ac
                      ,c54a62f2be9ef76efb1f3930ad81ea7f60defc1f5f25e09b7c067a815ae0c6cb
                      ,efa3f510ac0681f3daee287ac2059203ba32b12fbdabb39b793f007417237f09
                      ,dc8b7ff90724d7327cffec5bc7fa5f15a522b125bb514dd9fee84186d1b785e3
                      ,aba1fa394253639b89c66f21323feb7e78ad306cfcd05e960601532461705fa1
                      ,30ba7d1c30d2aa58c7f8022168049c7340ced60e246b24feef82cfae364cfcd1
                      ,9b08d5fd7caf602e32d075307a27d03654b01d61c47972a67d1b84cd42cff648
                      ,fb4bab3d6036ac1d730fa83d7366df1dd2dfeac194ef335d6854d8a6c6475542
                      ,0b04d8a27f2cd7a61d08d16678eb15f241f29a166ae76276013dc43c8631c8d3
                      ,7a8d18f1399979383fc374e5368fffa9349e693d9c117c6eb255b7210407a6df
                      ,664e39d07e6f971c0f1db832132504ddd96d048255b977192764a55205f780fc
                      ,a8bd65b3b05ff4fcf4a5fe75434bbbabc18e4a858c84848a79e5d11eca2670de
                      ,c6b32fd7eec3490795229bf7cd825b153197c5fca36726dc66a373375d8b9613
                      ,7db47b3921645c557fcc9bc3c43befd7b09857500646dc9cabb95d1196c9ab79
                      ,e46a166a5c98d313c323b01259d17bcee9bd369d4011e958742baf52002bee19
                      ,b69989a6a94fd03dea32002ff326a5ee7aa3cc96daa6435a335c4aff1c9edca7
                      ,4ef12b8542bdb4d2df74227f476efe949f16ad254ca49498d23f9f76e1875aa7
                      ,e61cb55da7a0cd5338673189b368dd6092330d0f5c7c58601b4cba9e0765079b
                      ,37c7e43b1d7188b1726f171fe93dc40a16648fadd6199a9a13097131cc54d06c
                      ,d519e4254830cc9413e9b230e33e8e65b731c01496ecf113186268aca71c4a70
                      ,8ebe9b161b194cd050665a4ae100ac79dff8f137bf670566645c27d76509789f
                      ,0693efa43c4860c9c7d5cf64586f514a2c6ed478a205f3495ad5629c3ba40e2e
                      ,b6526334ec61a3a71aea09b5b8df171c3b369f877beb2a23a047d595e9f0524b
                      ,eb77e594e816edef103a09c2ac2b31d35da10c8795e158d351785e295a9c3f9f
                      ,0261cbccef5146ffd325eb0d074905908acc11a4a234157697d42350f5ec6a7d
                      ,553b7f4a59439db7781448957396672b29b8741a823fb3765883803b7c73cbb9
                      ,1c76c2d8d6b23a85dea26055ca2c1dc211f8d92ce9f3dad5d7cff40d9b999ca8
                      ,004276e6929e3757095c47be73a48b40051212283cbbbd88d1ebf048f62ca522
                      ,011e42fcfa43368ed5f74957454778e09fa42d7e35aaa6123a4c37a3edf9d688
                      ,80747c1e6ed0878bee4dec7cfc8270faf6706b233961378117b59e7c9845bb73
                      ,14b447ae2e924e7002c28f0b7ce8ef98a576a11b2e8a6616b947ca678e7f0dfb
                      ,511be7f184173808e808d69f9e03f6006cabe3c1c99533765c12510270dea0a6
                      ,1ba411b5d8b7e39e3c8fe8033a341d8b1d347a25c9d505e9a6d6a49d854269cb
                      ,1f339ff5754d60e7959cf5c630d1af65bf30b6d7179d25abbc209f5c3d1cb433
                      ,33f95ee59920523732b1c54cb797c49e0850b63f84fc1f72dba1b2ddca19c6ba
                      ,ee961a33c36a66d7d35d868a94e8c69dc7d712f302521164295e79b33a84541f
                      ,dc8b21ac0aab78a2607f59d9856ba71f943dd145e287b2d95d119937058262f5
                      ,344d44dc0cae243ec0fd627262d6fc93084baa714165d4a2a2c0b8e7bd2f2b21
                      ,ba0eb9604235552767fb8cbabf72c54d5db699600f2dff12da73ae1e81908480
                      ,bdd23d8d5c91fcec75fe31f559a36498e4ead0a6fab9de97d9d21fe9ae011f3b]

  }
}
```

# sigStruct

This command is smilar to metaInfo, except it prints the
contents of SigStruct that might be stored in a seperate
file. One reason for doing this is to allow an HSM (Which
might be on an air-gapped network) to sign the enclave
(although it's unclear why computing MRENCLAVE outside of an
HSM is acceptable!!!).

```
$ ./dist/build/sgxTools/sgxTools sigStruct -h
Invalid option `-h'

Did you mean one of these?
    -i
    -c

Usage: sgxTools sigStruct (-i|--sig-struct SIGSTRUCT .bin FILENAME)
                          [-c|--nocolor]
                          Display contents of a CSS File

```

Actual run of the command


```
$ ./dist/build/sgxTools/sgxTools sigStruct -i /opt/intel/sgxpsw/aesm/le_prod_css.bin
{
  Vendor           : Intel
  Build Date       : 22-Jan-2018
  Product ID       : 32
  Software Version : 1
  MrEnclave        : 0x8b659cf36fbd3b8a9077fefd64bfddf61ba391101db525bd1159ab5324c3dc9c
  MrSignger        : 0xacb77012053e05a63d413b8bbae8fb6c5d73b3f2996d91c43bbbf90959c0f8d4
  Misc Select      : MiscSelect {miscExInfo = False, miscReserved_bit1_32 = 0}
  Misc Mask        : MiscSelect {miscExInfo = True, miscReserved_bit1_32 = 0}
  Attributes       :
    {
      DEBUG         : False
      MODE64        : True
      PROVISION_KEY : False
      LAUNCH_KEY    : True
      XFRM          :
        {
          XFRM Enabled    : True
          XCR0            : 3
          XSAVE available : False

        }

    }
  RSA exponent     : 3
  RSA Modulus      : 0xb78adbb6f40abfc3ff5a8397ab07866d6e762c7a66588d4d0fff8511e4581d866716641ae310c942127233ec388c94d1f189780a424f5632c7af77bea3f50a21f3008276f8bdeec7aa9f6fe6c765437fd82d8e88d29e248dcefa2b208c5b2bb473e06bc735937da11b8e1b2c46d1f77f5ed84218ab0c8adb100a89910d1874ed2729ef58e8c769c35c98651ac84446ecdcbdfe7da32eb51ae304a324effbe83168ebb8720c8c58261fb242f38cafa73b43438c8c1aa652fb07e996eb35b04877ee610b06aae14e3ea14e4118d22d098b75106d6167ca1447361c4b03eec25767d0049609dfb8fe6bd53252adfd875871711a85028681fdaff6a9b6fc8126bb2505e727fc29f55743f06c7aa2cdf523aadef55dbdd486d7bb5b65cb31e4fa5dfa2876558fad80a500f16d85a9f8d7f39b38dd4dbdc2e5b8f997ca145c18777a5181e8a3fa5345e444d573ba01d846dde55b06cae93eeaa843c22aa09ab9337b7b4d4b454ac8c7cb1b5866a8538f03c1ea208c79e2e54d76d01c09d9d7d1de479f
  RSA Signature    : 0x396123bc68bae29c07065586d1b438ed3d977e34b215efc099db28781c2bc08ac484c5c88cb1b4bf29c9af4ac1ad84c72d70928df51554fecc91548e5a02483cd046f212bd457e39f1a4b2a8d42fbb0eab68fc8740b2964258f37b15231147a2003522956feb7ba6c675ae574ec377fbe3a4ed65842968d55c212203707a86690842c2cc865f5030878099528ba51d42f3bd33a3dc13e55eebf0561a50d23db5b2d964bb3c026cc4eb2d51262d643982fe36cd53dce1d2b877415e3030e691dfe1729286f68873039152c742826371f661006731e630b1c22098f49a1202f4aba028fcd200dece0cf6063d7780e6eb63eccfd1db69ee4dc4a7a412968768603d866041e4178ac5c58408ada4d8fe1260ff3920308a194f0601d00c0a149d2b405640add2b35c4d53aca9b030231d6ae99c244fccd3fb0b67ba1cb1b84b2194ab30cde8daffc9a9c7525b7657ab49c92c5af8f22b8fcee8f9e8e0a7d4fe46921ef5bc05178452e8eeb34eeddd41a967fb35db5f59cc070d3cb2af603badef6ff5
  RSA Q1           : 0x11f0270ef2270b24733d1411fb38fd6fcfc3316817b87cac0e52c0915e0ba6d0cddb349a91037a2bfbfea020f605cf80b79ed5a2b2e94d1e3f5dce0c5f9932f75dc8ee2e4006cbaf721ad48dd5a71d757e3d2c02c76d7f38ea688550895bdcd928dbd6924f70b8a859a17029f0a68e1e58218b1ab2384cdc9b6d82657b623edc5be403d42ef7bda459661c3d917737f9bee9d244b6172827e5e7a1b885892a7fa087310dbaf4e182c60324d45ff93bc1b66300cd7062ad6ba923717fee2b5607305a7a7b7ca8830c662023668958a2ae63f155a55ae39aa28f0e918f56a726a46541b60ce44225e7cf68efbe801b2b0673809462aa52deee40a96b19c225fad84db87cfc71cddfb67c60327a3d8e0e45c6cabdc4901c9df54a16bb9249405ada9d6e29fb12af2e455a65be0a4c6e6cf787bc4a401d56a20b645954393816b36611d27be6d4059650093c0821a1459ea22407cbce043465ffbb97ddc885ece43af0383981066768d9312e6e9b7404af11d1da36e1a509ff8b99e9d216cb4a561f
  RSA Q2           : 0x35d97bbce3548f3b3e4075170cf76bde6dc4695ac9b930c5f211e35a558d340b3363ffd87984ec5f0ef9b2c4ae76e4a7e20ef9a48e4c057347af9452a029df9ded3973039e42ee6f7f13ca0df27776687f9fba27454d78d72cdb9ddeaf95e1219018212a2db69f292c25a1e82ea64f8d8b15956b7384ddab123998625b2ce1285ad4aa19f27caba1f6659436857865728deb0bcad1804a87e6be208ca7c14b6d510fabb77543cc35ed5e2cf629a73c2d374df31ae15529b53118fe6249bf7b27d47794829fb9dcf3e246add3feb3e2f6ead6a52f446db59bb66862fe7a7eb49201d74124cf9fa6979ff24b6900da5219e8e4d2768ba9f6ceb8cafcfdb82125f567ade85f8c3b7d3aebb42c0d8b68d3dbf87a0c48169d20a67ee876329fd919df4fba9d8ecdd1b9f2ebe4143b874e548c681de1cc7d49757d321a803bf2e74fe40da0830dd22252891d0c942bab843affd1d27391c6599486719066a01f0cd092d231e9eef8d975b298d5853c8909c2fdaaaee31bbcac86737fe5fcd381f90edd

}
```
