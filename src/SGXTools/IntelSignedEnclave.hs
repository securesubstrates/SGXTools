{-# LANGUAGE RankNTypes        #-}
{-# LANGUAGE OverloadedStrings #-}
module SGXTools.IntelSignedEnclave where

import qualified Data.ByteString      as B
import qualified Data.ByteString.Lazy as L
import           Control.Monad (replicateM_)
import           Crypto.Hash
import           SGXTools.Types
import           SGXTools.Marshalling
import           SGXTools.Utils (toHexRep)
import           Data.Binary
import           Data.Binary.Put
import           Data.Binary.Get (runGetOrFail)
import           Data.Bits
import           Data.ElfEdit
import           Text.Printf (printf, PrintfArg)
import           Text.PrettyPrint.ANSI.Leijen


data SGXELFError = SGXELFError String deriving (Show)

sgx_metadata_name :: B.ByteString
sgx_metadata_name = "sgx_metadata\0"

getEnclaveMetadataRaw :: Elf w -> Either SGXELFError B.ByteString
getEnclaveMetadataRaw e = case allNotes e of
  Left  s     -> Left (SGXELFError s)
  Right notes -> getMetadata notes
  where
    getMetadata :: [ElfNote a] -> Either SGXELFError B.ByteString
    getMetadata notes =
      case filter (\x -> noteName x == sgx_metadata_name) notes of
        [note] -> Right $ noteDesc note
        _      -> Left (SGXELFError "Too few or too many sgx_metadata sections")


bsSlice :: (Integral a) => a -- offset
        -> a -- Size
        -> B.ByteString
        -> B.ByteString
bsSlice off sz = (B.take (fromIntegral sz)) . (B.drop (fromIntegral off))

extractPatchData :: B.ByteString -- raw metadata from start
                 -> PatchEntry   -- Input patch entry
                 -> PatchEntry   -- output patch entry
extractPatchData bs p@(PatchEntry _ src sz _) =
  p{ patchData = B.take (fromIntegral sz) $!
                 B.drop (fromIntegral src) bs }

parseLayoutAndPatches :: B.ByteString     -- raw metadata from start
                      -> EnclaveMetadata  -- parsed metadata
                      -> Either SGXELFError EnclaveMetadata
parseLayoutAndPatches bs md = do
  let patchDD  = (metaDataDirectory md) !! ddPatchIndex
  let layoutDD = (metaDataDirectory md) !! ddLayoutIndex
  let patchSlice = L.fromChunks [bsSlice (ddOffset patchDD) (ddSize patchDD) bs]
  let layoutSlice = L.fromChunks [bsSlice (ddOffset layoutDD) (ddSize layoutDD) bs]
  p <- case runGetOrFail getPatches patchSlice of
         Left(_,_, s)    -> Left (SGXELFError $
                                  "Failed to parse Patches: " ++s )
         Right (_,_, m) -> Right $! fmap (extractPatchData bs) m

  l <- case runGetOrFail getLayouts layoutSlice of
         Left(_,_, s)   -> Left (SGXELFError $
                                  "Failed to parse Layout: " ++s )
         Right (_,_, m) -> Right m
  return $! md { metaPatches = p, metaLayouts = l }


processMetadata :: (Elf w) -> Either SGXELFError EnclaveMetadata
processMetadata elfFile = do
  bytes <- getEnclaveMetadataRaw elfFile
  partial <- case runGetOrFail getMetadata (L.fromChunks [bytes]) of
               Left  (_, _, s) -> Left (SGXELFError s)
               Right (_, _, m) -> Right m
  parseLayoutAndPatches bytes partial

getEnclaveMetadata :: B.ByteString -> Either SGXELFError EnclaveMetadata
getEnclaveMetadata bs =
  case parseElf bs of
    Elf32Res err e32
      | null err  -> processMetadata e32
      | otherwise -> Left $ SGXELFError (show err)
    Elf64Res err e64
      | null err  -> processMetadata e64
      | otherwise -> Left $ SGXELFError (show err)
    ElfHeaderError _ e -> Left $ SGXELFError (show e)

hexNumber :: (Integral a, PrintfArg a) => a -> String
hexNumber x = printf "0x%x" x

keyColor :: Bool  -- Use color
         -> Doc   -- Input doc
         -> Doc
keyColor True  = bold . blue
keyColor False = id

boldColor :: Bool  -- USe color
          -> Doc   -- Input doc
          -> Doc
boldColor True = bold
boldColor False = id

hexNumberWidth :: (Integral a, PrintfArg a) => Int -> a -> String
hexNumberWidth len x = "0x" ++ padding ++ p
  where
    p = printf "%x" x
    p_len = length p
    padding = if p_len >= len
              then ""
              else take (len - p_len) $ repeat '0'

formatKVPDoc :: Bool  -- Use color
             -> [(String, Doc)]
             -> Doc
formatKVPDoc c xs =
  let
    lenMax :: (String, a) -> Int -> Int
    lenMax (x,_) old = let l = length x
                       in if l > old
                          then l
                          else old
    max_key_len = foldr lenMax 0 xs
    paddedStr (key, value) = (fill max_key_len ((keyColor c . text) key)) <+>
                             colon <+> value
    innerDoc =
      foldr (\(k,v) ->
                \y ->
                  paddedStr (k, v) <> linebreak <> y) empty xs
  in
    lbrace <> linebreak <>
    indent 2 innerDoc   <>
    indent (-2) linebreak <>
    rbrace

toTCSPolicy :: Word32 -> TCS_POLICY
toTCSPolicy w | w == 0    = TCS_POLICY_BIND
              | w == 1    = TCS_POLICY_UNBIND
              | otherwise = undefined

ppXFRM :: Bool -- use color
       -> XFRM
       -> Doc
ppXFRM c xfrm = formatKVPDoc c kvps
  where
    kvps = [
      ("XFRM Enabled", show2Doc $! xfrmEnabled xfrm)
      , ("XCR0", show2Doc $! xfrmXCR0 xfrm)
      , ("XSAVE available", show2Doc $! xfrmHasXSave xfrm)
      ]

tabWidth :: Int
tabWidth = 2

embed :: Doc -> Doc
embed d = linebreak <> indent tabWidth d

ppAttributes :: Bool -- use color
             -> Attributes
             -> Doc
ppAttributes c attr = formatKVPDoc c kvps
  where
    kvps = [
  --    ("EINIT", show2Doc $! attrInit attr)
       ("DEBUG", show2Doc $! attrDebug attr)
      , ("MODE64", show2Doc $! attrMode64Bit attr)
      , ("PROVISION_KEY", show2Doc $! attrProvisionKey attr)
      , ("LAUNCH_KEY", show2Doc $! attrEinitTokenKey attr)
      , ("XFRM", embed $! ppXFRM c $! attrXFRM attr)
      ]

show2Doc :: (Show a) => a -> Doc
show2Doc x = text $! show x

ppMetadata :: Bool  -- show layout
           -> Bool  -- Show patch dir
           -> Bool  -- useColor
           -> EnclaveMetadata -> Doc
ppMetadata l p c m = formatKVPDoc c kvps
  where
    kvps = kvpBase ++
           (if l then kvpLayout else [] ) ++
           (if p then kvpPatch else [] )

    kvpLayout = [("Layout", embed $! ppLayouts c $! (metaLayouts m))]
    kvpPatch = [("Patches", embed $! ppPatches c $! (metaPatches m))]
    kvpBase =
      [
        ("Magic", text $! hexNumberWidth 8 (metaMagicNum m))
      , ("Version", text $! hexNumberWidth 8 (metaVersion m))
      , ("Metadata Size", show2Doc $! metaSize m)
      , ("Thread Binding", show2Doc $! toTCSPolicy $! metaTCSPolicy m)
      , ("SSA Frame Size", show2Doc $! metaSSAFrameSize m)
      , ("Max Save Buffer", show2Doc $! metaMaxSaveSize m)
      , ("Desired MISC Select", show2Doc $! metaDesiredMiscSel m)
      , ("Minimum Thread Pool", show2Doc $! metaTCSMinPool m)
      , ("Enclave Size", show2Doc $! metaEnclaveSize m)
      , ("Enclave Attributes", embed  $! ppAttributes c $! metaAttributes m)
      , ("SigStruct", embed $! ppSigStruct c $! metaEnclaveCSS m)
      --  , ("Layout", embed $! ppLayouts $! (metaLayouts m))
      --      , ("Data Directory", embed $! ppDataDirectories $! metaDataDirectory m)
      --      , ("Patches", embed $! ppPatches $! (metaPatches m))
      ]

ppSigStruct :: Bool -- use color
            -> SigStruct
            -> Doc
ppSigStruct c s = formatKVPDoc c [
  ("Vendor", show2Doc $! ssVendor s)
  , ("Build Date", show2Doc $! ssBuildDate s)
  , ("Product ID", show2Doc $! ssIsvProdId s)
  , ("Software Version", show2Doc $! ssIsvSvn s)
  , ("MrEnclave", (boldColor c . text) $! "0x" ++ (toHexRep (ssEnclaveHash s)))
  , ("Misc Select", show2Doc $! ssMiscSelect s)
  , ("Misc Mask", show2Doc $! ssMiscMask s)
  , ("Attributes", embed $! ppAttributes c $! (ssAttributes s))
    -- , ("Attributes Mask", embed $! ppAttributes $! (ssAttributesMask s))
  , ("RSA exponent", show2Doc $! (ssExponent s))
  , ("RSA Modulus", text $! hexNumber $! ssModulus s)
  , ("RSA Signature", text $! hexNumber $! (ssSignature s))
  , ("RSA Q1", text $! hexNumber $! ssQ1 s)
  , ("RSA Q2", text $! hexNumber $! ssQ2 s)
  ]


ppDataDirectory :: Bool -- color
                -> DataDirectory
                -> Doc
ppDataDirectory c dd = formatKVPDoc c [
  ("Offset", show2Doc $! ddOffset dd)
  , ("Size", show2Doc $! ddSize dd)
  ]


ppDataDirectories :: Bool -- use color
                  -> [DataDirectory]
                  -> Doc
ppDataDirectories c = list . fmap (ppDataDirectory c)

ppPatch :: Bool -- use color
        -> PatchEntry
        -> Doc
ppPatch c p = formatKVPDoc c [
  ("Dest", text $! hexNumber $! patchDest p)
  , ("Source", text $! hexNumber $! patchSource p)
  , ("Size", show2Doc $! patchSize p)
  , ("Content", show2Doc $!
                toHexRep $!
                L.fromChunks [patchData p])
  ]

ppPatches :: Bool
          -> [PatchEntry]
          -> Doc
ppPatches c = list . fmap (ppPatch c)

ppLayout :: Bool
         -> LayoutEntry
         -> Doc
ppLayout c (LayoutEntry id ops count rva csz coff perm) =
  formatKVPDoc c [
  ("Layout ID", show2Doc id)
  , ("Layout Ops", show2Doc ops)
  , ("Page Count", show2Doc count)
  , ("Layout RVA", text $! hexNumber rva)
  , ("Content Size", show2Doc csz)
  , ("Content Off", show2Doc coff)
  , ("Permissions", list (fmap (\x -> show2Doc x) perm))
  ]
ppLayout c (LayoutGroup id lcount ltimes lstep _) =
  formatKVPDoc c [
  ("Group ID", show2Doc id)
  , ("Entry count", show2Doc lcount)
  , ("Load Times", show2Doc ltimes)
  , ("Load Step", show2Doc lstep)
  ]

ppLayouts :: Bool
          -> [LayoutEntry]
          -> Doc
ppLayouts c = list . fmap (ppLayout c)

ppEinitToken :: Bool
             -> EInitToken
             -> Doc
ppEinitToken c emd = formatKVPDoc c [
  ("MrEnclave",
    text $! "0x" ++ (toHexRep
                       (eitMrEnclave emd)))
  , ("MrSigner",
      text $! "0x" ++ (toHexRep
                        (eitMrSigner emd)))
  , ("Launch Token (CMAC)",
     text $! "0x" ++ (toHexRep (eitMAC emd)))
  , ("Key Diversification",
      text $! "0x" ++ (toHexRep (eitKeyId emd)))
  , ("Product ID", show2Doc $! eitIsvProdIdLe emd)
  , ("Software Version", show2Doc $! eitIsvSvnLe emd)
  , ("Debug Enabled", show2Doc $! eitDebug emd)
  , ("CPUSVN", show2Doc $! eitCpuSvnLe emd)
  , ("Enclave Attributes", embed $! ppAttributes c $!
                           (eitAttributes emd))
  , ("LE MiscSelect",
     show2Doc $! eitMaskedMiscSelectLe emd)
  , ("LE Attributes",
      embed $! ppAttributes c $! (eitMaskedAttributes emd))
  ]


mPageSize :: (Num a) => a
mPageSize = 4096

mDataBlockSize :: (Num a) => a
mDataBlockSize = 64

mEextendStep :: (Num a) => a
mEextendStep = 256

word32tolistLE :: Word32 -> [Word8]
word32tolistLE x =
  fmap (\i -> fromIntegral $! (x `shiftR` (8*i)) .&. 0xff) [0..3]
{-# INLINE word32tolistLE #-}

word64tolistLE :: Word64 -> [Word8]
word64tolistLE x =
  fmap (\i -> fromIntegral $! (x `shiftR` (8*i)) .&. 0xff) [0..7]
{-# INLINE word64tolistLE #-}


ecreateDataBlock ::  Word32 -- ssa_frame_size
                 -> Word64 -- enclave size
                 -> L.ByteString
ecreateDataBlock ssa sz = runPut ecreateBuilder
  where
    ecreateBuilder :: Put
    ecreateBuilder = do
      putByteString "ECREATE\0"
      putWord32le ssa
      putWord64le sz
      putByteString $! B.replicate (mDataBlockSize - 8 - 4 - 8) 0


eaddDataBlock :: Word64  -- offset
              -> SecInfo -- secinfo
              -> L.ByteString
eaddDataBlock off sec = L.take mDataBlockSize $! runPut eaddBuilder
  where
    eaddBuilder :: Put
    eaddBuilder = do
      putByteString "EADD\0\0\0\0"
      putWord64le off
      putSecInfo sec


eextendDataBlock :: Word64  -- offset
                 -> L.ByteString
eextendDataBlock w = runPut eextendBuilder
  where
    eextendBuilder :: Put
    eextendBuilder = do
      putByteString "EEXTEND\0"
      putWord64le   w
      replicateM_ (mDataBlockSize - 8 - 8) $! (putWord8 0)


measureEcreate :: Word32         -- ssa_frame_size
               -> Word64         -- enclave size
               -> Context SHA256 -- hash context
measureEcreate ssa_len enc_sz = hashUpdates shaState ecreateData
  where
    shaState :: Context SHA256
    shaState = hashInitWith SHA256
    ecreateData :: [B.ByteString]
    ecreateData = L.toChunks $! ecreateDataBlock ssa_len enc_sz


measureEadd :: Context SHA256 -- SHA256 context
            -> Word64         -- Offset
            -> SecInfo        -- SecInfo
            -> Context SHA256 -- output hash state
measureEadd shaState off sec = hashUpdates shaState $! eaddData
  where
    eaddData :: [B.ByteString]
    eaddData = L.toChunks $! eaddDataBlock off sec

measureExtendPage :: Context SHA256 -- SHA256 context
                  -> Word32         -- Page offset
                  -> L.ByteString   -- Page content
                  -> Context SHA256 -- Output hash state
measureExtendPage shaState off bs = mep 0 shaState
  where
    eextendHdr :: Word64 -> L.ByteString
    eextendHdr c = eextendDataBlock $!
                   c + fromIntegral off

    dataToHash :: Word64 -> L.ByteString
    dataToHash c = L.take mEextendStep $!
                   L.drop (fromIntegral c) bs

    dataToHashWithHdr :: Word64 -> [B.ByteString]
    dataToHashWithHdr c = L.toChunks $!
                          L.append (eextendHdr c) (dataToHash c)

    mep :: Word64 -> Context SHA256 -> Context SHA256
    mep c h
      | c         >= mPageSize = h
      | otherwise =  mep (c+mEextendStep) $!
                     hashUpdates h (dataToHashWithHdr c)


measureEnclave :: B.ByteString -> Either SGXELFError (Digest SHA256)
measureEnclave bs =
  case parseElf bs of
    Elf32Res err e32
      | null err  -> measure e32
      | otherwise -> Left $ SGXELFError (show err)
    Elf64Res err e64
      | null err  -> measure e64
      | otherwise -> Left $ SGXELFError (show err)
    ElfHeaderError _ e -> Left $ SGXELFError (show e)


findPT_LOAD ::  Elf w -> [ElfSegment  w]
findPT_LOAD e = filter (\x -> elfSegmentType x == PT_LOAD) (elfSegments e)

findPT_TLS :: Elf w -> [(ElfSegment w)]
findPT_TLS e = filter (\x -> elfSegmentType x == PT_TLS) (elfSegments e)


measure :: Elf w -> Either SGXELFError (Digest SHA256)
measure e = do
  md <- processMetadata e
  let
    ssa_sz = metaSSAFrameSize md
    enc_sz = metaEnclaveSize md
    ecHash = measureEcreate ssa_sz enc_sz
  return $! hashFinalize ecHash
