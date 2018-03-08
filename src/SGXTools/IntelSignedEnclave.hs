{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE OverloadedStrings #-}
module SGXTools.IntelSignedEnclave where

import SGXTools.Types
import SGXTools.Marshalling
import Data.Binary.Get (runGetOrFail)
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as L
import Data.ElfEdit

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
