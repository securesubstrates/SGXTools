{-# LANGUAGE RankNTypes                #-}
{-# LANGUAGE FlexibleContexts          #-}
{-# LANGUAGE DataKinds                 #-}
{-# LANGUAGE OverloadedStrings         #-}
{-# LANGUAGE ExistentialQuantification #-}
{-# LANGUAGE TypeFamilies              #-}
{-# LANGUAGE GADTs                     #-}

module SGXTools.IntelSignedEnclave where

import qualified Data.ByteArray       as BA
import qualified Data.ByteString      as B
import qualified Data.ByteString.Lazy as L
import qualified Control.Monad.State.Strict as S
import qualified Control.Monad.Reader       as R
import qualified Control.Monad.Trans        as T
import qualified Data.Vector                as V
import           Control.Monad (replicateM_, forM_, when)
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
-- import           Debug.Trace


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


extractLayoutData :: B.ByteString  -- raw metadata from start
                  -> LayoutEntry   -- Input Layout entry
                  -> LayoutEntry   -- Updated Layout Entry
extractLayoutData bs l@(LayoutEntry _ _ _ _ _ sz off _)
  | off == 0  = l
  | otherwise = l { lentryContent = bsSlice off sz bs }
extractLayoutData bs l = l  -- For Layout group

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
         Right (_,_, m) -> Right $! fmap (extractLayoutData bs) m
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
                \y -> paddedStr (k, v) <> linebreak <> y) empty xs
  in
    lbrace                <>
    linebreak             <>
    indent 2 innerDoc     <>
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
ppLayout c (LayoutEntry id ops count rva co csz coff perm) =
  formatKVPDoc c $! [
  ("Layout ID", show2Doc id)
  , ("Layout Ops", show2Doc ops)
  , ("Layout RVA", text $! hexNumber rva)
  , ("Page Count", show2Doc count)
  , ("Content Size", show2Doc csz)
  , ("Content Off", show2Doc coff)
  , ("Content", show2Doc $ toHexRep $ L.fromChunks [co])
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


eextendHdrBlock :: Word64  -- offset
                 -> L.ByteString
eextendHdrBlock w = runPut eextendBuilder
  where
    eextendBuilder :: Put
    eextendBuilder = do
      putByteString "EEXTEND\0"
      putWord64le   w
      replicateM_ (mDataBlockSize - 8 - 8) $! (putWord8 0)


measureEnclave :: B.ByteString -> Either SGXELFError B.ByteString
measureEnclave bs =
  case parseElf bs of
    Elf32Res err e32
      | null err  -> undefined -- measure e32
      | otherwise -> Left $ SGXELFError (show err)
    Elf64Res err e64
      | null err  -> measureEnclave64 e64 bs
      | otherwise -> Left $ SGXELFError (show err)
    ElfHeaderError _ e -> Left $ SGXELFError (show e)


phdrList :: Elf w -> [Phdr w]
phdrList = allPhdrs . elfLayout


findPT_LOAD ::  Elf w -> [Phdr  w]
findPT_LOAD e = filter isLOAD $ phdrList e
  where
    isLOAD :: Phdr w -> Bool
    isLOAD h = (PT_LOAD == elfSegmentType (phdrSegment h))


findPT_TLS :: Elf w -> [Phdr w]
findPT_TLS e = filter isTLS $ phdrList e
  where
    isTLS :: Phdr w -> Bool
    isTLS h = PT_TLS == elfSegmentType (phdrSegment h)


data ImageInfo = ImageInfo {
  elfImageInfo :: (Elf 64)
  , metaInfo   :: EnclaveMetadata
  , rawImage   :: B.ByteString
  }

type HashState h m a =
  R.ReaderT ImageInfo (S.StateT h m) a

getHashCtx :: (Monad m) => HashState h m h
getHashCtx = T.lift S.get

putHashState :: (Monad m, HashAlgorithm h)
  => (Context h)                  -- Updated context
  -> HashState (Context h) m ()
putHashState = T.lift . S.put


updateManyHashState :: (Monad m, HashAlgorithm h)
                => [B.ByteString]
                -> HashState (Context h) m ()
updateManyHashState ds = do
  ctx <- getHashCtx
  putHashState $! hashUpdates ctx ds


updateHashState :: (Monad m, HashAlgorithm h)
                => B.ByteString
                -> HashState (Context h) m ()
updateHashState bs = do
  ctx <- getHashCtx
  putHashState $! hashUpdate ctx bs


askRawImage :: (Monad m) =>
            HashState h m B.ByteString
askRawImage = fmap rawImage R.ask


askRawSlice :: (Monad m)
            => Word64   -- Start offset
            -> Word64   -- size of slice
            -> HashState h m B.ByteString
askRawSlice off sz = do
  imgInfo <- R.ask
  pure $ bsSlice off sz $ rawImage imgInfo

askElf :: (Monad m)
       => HashState h m (Elf 64)
askElf = fmap elfImageInfo R.ask


askMeta :: (Monad m)
        => HashState h m EnclaveMetadata
askMeta = fmap metaInfo R.ask


readElf :: (Monad m)
            => (Elf 64 -> a)
            -> HashState h m a
readElf fn = R.reader  (fn . elfImageInfo)


readMeta :: (Monad m)
             => (EnclaveMetadata -> a)
             -> HashState h m a
readMeta fn = R.reader (fn . metaInfo)

ecreate :: (Monad m, HashAlgorithm h)
        => HashState (Context h) m ()
ecreate = do
  ssa_sz <- readMeta metaSSAFrameSize
  enc_sz <- readMeta metaEnclaveSize
  let ecreateData = ecreateDataBlock ssa_sz enc_sz
  updateManyHashState $! L.toChunks $! ecreateData
    -- (trace ("EC: 0x" ++ toHexRep ecreateData) ecreateData)


eadd :: (Monad m, HashAlgorithm h)
     => Word64         -- offset
     -> SecInfo        -- SecInfo flags
     -> HashState (Context h) m ()
eadd off sec = do
  let eaddData = eaddDataBlock off sec
  updateManyHashState $! L.toChunks $! eaddData
    -- (trace ("EA: 0x" ++ toHexRep eaddData) eaddData)


eextend :: (Monad m, HashAlgorithm h)
        => Word64          -- Page Offset
        -> B.ByteString    -- Page Data content
        -> HashState (Context h) m ()
eextend off bs = go 0
  where
    go :: (Monad m, HashAlgorithm h)
      => Word64
      -> HashState (Context h) m ()
    go consumed
      | consumed >= mPageSize = return ()
      | otherwise             = do
          let chunk = bsSlice consumed mEextendStep bs
              hdr   = eextendHdrBlock (off + consumed)
              tbhData = L.append hdr
                        (L.fromChunks [chunk])
          updateManyHashState $! L.toChunks $! tbhData
            -- (trace ("EE: 0x" ++ toHexRep tbhData) tbhData)
          go $! (consumed + mEextendStep)


segmentFlagsToSIFlags ::  ElfSegmentFlags -> SecInfo
segmentFlagsToSIFlags (ElfSegmentFlags w) =
  SecInfo flags
  where
    m :: (Num a, Bits a) => [(a, SecInfoFlags)]
    m = [ (0, SI_FLAG_X)
        , (1, SI_FLAG_W)
        , (2, SI_FLAG_R)]

    flags :: [SecInfoFlags]
    flags = SI_FLAG_REG : (fmap snd $
      filter (\(x,y) -> w .&. (1 `shiftL` x) /= 0) m)

data SI w = SI {
    siData :: B.ByteString
  , pageCount :: Word64
  , pageOff   :: ElfWordType w
  , flags     :: SecInfo
  }



getSegmentData64 :: (Phdr 64)
                 -> B.ByteString
                 -> (SI 64)
getSegmentData64 phdr raw =
  let
    seg :: (ElfSegment 64)
    seg = phdrSegment phdr

    f :: SecInfo
    f = segmentFlagsToSIFlags $ elfSegmentFlags seg

    fileOff :: (ElfWordType 64)
    fileOff = case phdrFileStart phdr of
                (FileOffset s) -> s

    padTop :: (ElfWordType 64)
    padTop = (elfSegmentVirtAddr seg) .&. (mPageSize - 1)

    virtTop :: (ElfWordType 64)
    virtTop = (elfSegmentVirtAddr seg) .&.
              (complement $! mPageSize - 1)

    virtBottom :: (ElfWordType 64)
    virtBottom = let last = (elfSegmentVirtAddr seg) +
                            (phdrMemSize phdr)
                     (q,r) = last `divMod` mPageSize
                 in if r == 0 then last
                    else last + (mPageSize - r )

    virtSz  :: (ElfWordType 64)
    virtSz = virtBottom - virtTop

    fileSz :: (ElfWordType 64)
    fileSz = phdrFileSize phdr

    padBottom :: Int
    padBottom = if (virtSz - padTop) > fileSz
                    then fromIntegral $!
                         virtSz - padTop - fileSz
                    else 0

    pageCount :: Word64
    pageCount = virtSz `div` mPageSize

    slice :: B.ByteString
    slice = B.concat
            [constantData8 (fromIntegral padTop) 0
            , bsSlice fileOff fileSz raw
            , constantData8 (fromIntegral padBottom) 0]

  in SI {
    siData      = slice `seq` slice
    , pageCount = pageCount `seq` pageCount
    , pageOff   = virtTop `seq` virtTop
    , flags     = f `seq` f
    }


measureSegment64 :: (Monad m, HashAlgorithm h)
                 => (Phdr 64)
                 -> HashState (Context h) m ()
measureSegment64 phdr = do
  pd <- readMeta metaPatches
  si <- fmap (getSegmentData64 phdr) askRawImage
  let rawData = siData si

  forM_ [0.. (pageCount si) - 1] $ \ i -> do
    let po      = mPageSize * i
    let rva     = (pageOff si) + po
    let page    = B.drop (fromIntegral po) $! rawData
    eadd rva (flags si)
    eextend rva $! page

constantPage :: Word32 -- Data to fill
             -> B.ByteString
constantPage w =
  L.toStrict $! runPut $!
  replicateM_ (mPageSize `div` 4) $ putWord32le w


constantData8 :: Int
             -> Word8
             -> B.ByteString
constantData8 c x = B.pack $ replicate c x


measureConstLayout :: (Monad m, HashAlgorithm h)
                   => LayoutEntry
                   -> HashState (Context h) m ()
measureConstLayout
  (LayoutEntry _ ops count rva _ sz d si) = do

  let
    pageData :: B.ByteString
    pageData = constantPage sz

  when (d /= 0) (fail "Invalid const Layout")

  forM_ [0 .. count - 1 ] $ \ i -> do
    let va = rva + mPageSize * fromIntegral i
    va `seq` eadd va (SecInfo si)
    when (E_EXTEND `elem` ops) (pageData `seq` eextend va pageData)


measureContentLayout :: (Monad m, HashAlgorithm h)
                     => LayoutEntry
                     -> HashState (Context h) m ()
measureContentLayout
  (LayoutEntry _ ops count rva c sz _ si) = do
  let
    contentPage :: B.ByteString
    contentPage =
      B.append c (constantData8 (fromIntegral (mPageSize - sz)) 0)

  forM_ [0 .. count - 1] $ \ i -> do
    let va = rva + mPageSize * fromIntegral i
    va `seq` eadd va (SecInfo si)
    when (E_EXTEND `elem` ops) $ do
      eextend va contentPage  -- The same page keeps getting added


measureLayout :: (Monad m, HashAlgorithm h)
              => LayoutEntry    -- Layout
              -> Word64         -- extra offset to add
              -> HashState (Context h) m ()
measureLayout l@(LayoutEntry lid ops _ rva _ _ off perm) rva_shift
  | lid == LAYOUT_ID_GUARD        = return ()
  | lid == LAYOUT_ID_ELF_SEGMENT  = return ()
  | perm == []                    = return ()
  | (E_ADD `notElem` ops)         = return ()
  | off == 0                      = measureConstLayout l{ lentryRVA = rva + rva_shift }
  | otherwise                     = measureContentLayout l{ lentryRVA = rva + rva_shift }
measureLayout g@(LayoutGroup _ _ _ _ _) _ = fail ("Cannot process group layout" ++ show g)


numberEntry :: [LayoutEntry] -> V.Vector (Word16, LayoutEntry)
numberEntry ls = V.fromList $! zipWith (\ i l -> (i, l)) [0..] ls


measureLayouts :: (Monad m, HashAlgorithm h)
               => HashState (Context h) m ()
measureLayouts = do
  nl <- fmap numberEntry (readMeta metaLayouts)
  forM_ nl $ \(index, layout) -> do
    case layout of
      (LayoutGroup lid count time step _) -> do
        forM_ [0..time-1] $ \ i -> do
          forM_ [index-count .. index-1] $ \j -> do
            let entry = snd $ nl V.! (fromIntegral j)
            let shift = step * fromIntegral i
            measureLayout entry shift
      _ -> measureLayout layout 0


measureImage64 :: (Monad m, HashAlgorithm h)
             => HashState (Context h) m ()
measureImage64 = do
  pt_load <- fmap findPT_LOAD askElf
  ecreate
  mapM measureSegment64 pt_load
  measureLayouts


patchOne :: PatchEntry
         -> B.ByteString
         -> B.ByteString
patchOne p bs =
  let
    c0 = B.take (fromIntegral (patchDest p)) bs
    c1 = patchData p
    c2 = B.drop (fromIntegral
                 (patchDest p +
                   fromIntegral (patchSize p))) bs
  in B.concat $! [c0, c1, c2]


patchImage :: B.ByteString
           -> [PatchEntry]
           -> B.ByteString
patchImage bs pd = foldr (\ p b -> patchOne p b) bs pd


measureEnclave64 :: Elf 64
                 -> B.ByteString
                 -> Either SGXELFError B.ByteString
measureEnclave64 e bs = do
  meta <- processMetadata e
  let io = ImageInfo e meta $! patchImage bs (metaPatches meta)
  hash <- S.execStateT (R.runReaderT measureImage64 io) (hashInitWith SHA256)
  return $ BA.convert $ hashFinalize hash
