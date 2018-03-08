{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE OverloadedStrings #-}
module SGXTools.IntelSignedEnclave where

import Data.Binary
import SGXTools.Types
import SGXTools.Marshalling
import Data.Binary.Get (runGetOrFail)
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as L
import SGXTools.Utils (toHexRep)
import Data.ElfEdit
import Text.Printf (printf, PrintfArg)
import Text.PrettyPrint.ANSI.Leijen

---------------- ELF Parsing stuff --------------------

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
         Right (_,_, m) -> Right m

  l <- case runGetOrFail getLayouts layoutSlice of
         Left(_,_, s)   -> Left (SGXELFError $
                                  "Failed to parse Layout: " ++s )
         Right (_,_, m) -> Right m
  return $! md { metaPatches = p, metaLayouts = l }


process :: (Elf w) -> Either SGXELFError EnclaveMetadata
process elfFile = do
  bytes <- getEnclaveMetadataRaw elfFile
  partial <- case runGetOrFail getMetadata (L.fromChunks [bytes]) of
               Left  (_, _, s) -> Left (SGXELFError s)
               Right (_, _, m) -> Right m
  parseLayoutAndPatches bytes partial

getEnclaveMetadata :: B.ByteString -> Either SGXELFError EnclaveMetadata
getEnclaveMetadata bs =
  case parseElf bs of
    Elf32Res err e32
      | null err  -> process e32
      | otherwise -> Left $ SGXELFError (show err)
    Elf64Res err e64
      | null err  -> process e64
      | otherwise -> Left $ SGXELFError (show err)
    ElfHeaderError _ e -> Left $ SGXELFError (show e)

hexNumber :: (Integral a, PrintfArg a) => a -> String
hexNumber x = printf "0x%x" x

hexNumberWidth :: (Integral a, PrintfArg a) => Int -> a -> String
hexNumberWidth len x = "0x" ++ padding ++ p
  where
    p = printf "%x" x
    p_len = length p
    padding = if p_len >= len
              then ""
              else take (len - p_len) $ repeat '0'

formatKVPDoc :: [(String, Doc)] -> Doc
formatKVPDoc xs =
  let
    lenMax :: (String, a) -> Int -> Int
    lenMax (x,_) old = let l = length x
                       in if l > old
                          then l
                          else old
    max_key_len = foldr lenMax 0 xs
    paddedStr (key, value) = (fill max_key_len ((bold . blue . text) key)) <+>
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

ppXFRM :: XFRM -> Doc
ppXFRM xfrm = formatKVPDoc kvps
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

ppAttributes :: Attributes -> Doc
ppAttributes attr = formatKVPDoc kvps
  where
    kvps = [
  --    ("EINIT", show2Doc $! attrInit attr)
       ("DEBUG", show2Doc $! attrDebug attr)
      , ("MODE64", show2Doc $! attrMode64Bit attr)
      , ("PROVISION_KEY", show2Doc $! attrProvisionKey attr)
      , ("LAUNCH_KEY", show2Doc $! attrEinitTokenKey attr)
      , ("XFRM", embed $! ppXFRM $! attrXFRM attr)
      ]

show2Doc :: (Show a) => a -> Doc
show2Doc x = text $! show x

ppMetadata :: EnclaveMetadata -> Doc
ppMetadata m = formatKVPDoc kvps
  where
    kvps =
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
      , ("Enclave Attributes", embed  $! ppAttributes $! metaAttributes m)
      , ("SigStruct", embed $! ppSigStruct $! metaEnclaveCSS m)
      , ("Layout", embed $! ppLayouts $! (metaLayouts m))
      --      , ("Data Directory", embed $! ppDataDirectories $! metaDataDirectory m)
      --      , ("Patches", embed $! ppPatches $! (metaPatches m))
      ]

ppSigStruct :: SigStruct -> Doc
ppSigStruct s = formatKVPDoc [
  ("Vendor", show2Doc $! ssVendor s)
  , ("Build Date", show2Doc $! ssBuildDate s)
  , ("Product ID", show2Doc $! ssIsvProdId s)
  , ("Software Version", show2Doc $! ssIsvSvn s)
  , ("MrEnclave", (bold . text) $! "0x" ++ (toHexRep (ssEnclaveHash s)))
  , ("Misc Select", show2Doc $! ssMiscSelect s)
  , ("Misc Mask", show2Doc $! ssMiscMask s)
  , ("Attributes", embed $! ppAttributes $! (ssAttributes s))
    -- , ("Attributes Mask", embed $! ppAttributes $! (ssAttributesMask s))
  , ("RSA exponent", show2Doc $! (ssExponent s))
  , ("RSA Modulus", text $! hexNumber $! ssModulus s)
  , ("RSA Signature", text $! hexNumber $! (ssSignature s))
  , ("RSA Q1", text $! hexNumber $! ssQ1 s)
  , ("RSA Q2", text $! hexNumber $! ssQ2 s)
  ]


ppDataDirectory :: DataDirectory -> Doc
ppDataDirectory dd = formatKVPDoc [
  ("Offset", show2Doc $! ddOffset dd)
  , ("Size", show2Doc $! ddSize dd)
  ]


ppDataDirectories :: [DataDirectory] -> Doc
ppDataDirectories = list . fmap ppDataDirectory

ppPatch :: PatchEntry -> Doc
ppPatch p = formatKVPDoc [
  ("Dest", text $! hexNumber $! patchDest p)
  , ("Source", text $! hexNumber $! patchSource p)
  , ("Size", show2Doc $! patchSize p)
  ]

ppPatches :: [PatchEntry] -> Doc
ppPatches = list . fmap ppPatch

ppLayout :: LayoutEntry -> Doc
ppLayout (LayoutEntry id ops count rva csz coff perm) =
  formatKVPDoc [
  ("Layout ID", show2Doc id)
  , ("Layout Ops", show2Doc ops)
  , ("Page Count", show2Doc count)
  , ("Layout RVA", text $! hexNumber rva)
  , ("Content Size", show2Doc csz)
  , ("Content Off", show2Doc coff)
  , ("Permissions", list (fmap (\x -> show2Doc x) perm))
  ]
ppLayout (LayoutGroup id lcount ltimes lstep _) =
  formatKVPDoc [
  ("Group ID", show2Doc id)
  , ("Entry count", show2Doc lcount)
  , ("Load Times", show2Doc ltimes)
  , ("Load Step", show2Doc lstep)
  ]

ppLayouts :: [LayoutEntry] -> Doc
ppLayouts = list . fmap ppLayout

ppEinitToken :: EInitToken -> Doc
ppEinitToken emd = formatKVPDoc [
  ("MrEnclave",
    (bold . text) $! "0x" ++ (toHexRep
                               (eitMrEnclave emd)))
  , ("MrSigner",
     (bold . text ) $! "0x" ++ (toHexRep
                                (eitMrSigner emd)))
  , ("Launch Token (CMAC)",
     text $! "0x" ++ (toHexRep (eitMAC emd)))
  , ("Key Diversification",
      text $! "0x" ++ (toHexRep (eitKeyId emd)))
  , ("Product ID", show2Doc $! eitIsvProdIdLe emd)
  , ("Software Version", show2Doc $! eitIsvSvnLe emd)
  , ("Debug Enabled", show2Doc $! eitDebug emd)
  , ("CPUSVN", show2Doc $! eitCpuSvnLe emd)
  , ("Enclave Attributes", embed $! ppAttributes $!
                    (eitAttributes emd))
  , ("LE MiscSelect",
     show2Doc $! eitMaskedMiscSelectLe emd)
  , ("LE Attributes",
     embed $! ppAttributes $! (eitMaskedAttributes emd))
  ]
