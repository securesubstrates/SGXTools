{-# LANGUAGE CPP #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE DataKinds  #-}

module SGXTools.Marshalling where

import SGXTools.Types
import Control.Monad (unless, replicateM_)
import Text.Printf   (printf)
import Data.Bits
import Data.Binary
import Data.Binary.Put
import Data.Binary.Get
import qualified Data.Binary.Builder  as BD
import qualified Data.ByteString.Lazy as L
import qualified Data.ByteString      as B

setBitIfTrue :: Bool
             -> Int
             -> Word8
setBitIfTrue t i = if t
                   then 0x1 `shiftL` i
                   else 0x0

getMiscSelect :: Get MiscSelect
getMiscSelect = do
  msBit <- getWord8
  skip 3
  return $! MiscSelect (msBit .&. 0x80 == 0x80) 0x00

putMiscSelect :: MiscSelect -> Put
putMiscSelect x = if miscExInfo x
                  then putWord32le 0x80
                  else putWord32le 0x0

putPadBytes :: Int   -- Pad count
            -> Word8 -- Pad value per byte
            -> Put
putPadBytes c = putBuilder . BD.fromLazyByteString . L.take c' . L.repeat
                where c' = fromIntegral c

getAttributes :: Get Attributes
getAttributes = do
  w        <- getWord8
  skip 7
  xf       <- getXFRM
  return $! Attributes {
    attrInit                = testBit w 0
    , attrDebug             = testBit w 1
    , attrMode64Bit         = testBit w 2
    , attrReserved_bit3     = False
    , attrProvisionKey      = testBit w 4
    , attrEinitTokenKey     = testBit w 5
    , attrReserved_bit6_63  = L.take 7 $! L.repeat 0x0
    , attrXFRM              = xf
    }


putAttributes  :: Attributes -> Put
putAttributes attr = do
  putWord8 topByte
  putPadBytes 7 0x0
  putXFRM (attrXFRM attr)
    where
      topByte :: Word8
      topByte =
        let
          isInit   = setBitIfTrue (attrInit  attr)     7
          isDebug  = setBitIfTrue (attrDebug attr)     6
          isMode64 = setBitIfTrue (attrMode64Bit attr) 5
          isReserved_bit3 = 0                       -- 4
          isProvK  = setBitIfTrue
                      (attrProvisionKey attr) 3
          isEinitK = setBitIfTrue
                      (attrEinitTokenKey attr) 2
        in isInit .|. isDebug .|. isMode64 .|.
           isReserved_bit3 .|. isProvK .|. isEinitK


parseAttributes :: L.ByteString -> Attributes
parseAttributes  = runGet getAttributes

getCPUSVN :: Get CPUSVN
getCPUSVN = do
  by <- getLazyByteString 16
  return  CPUSVN { cpuSvnValue = by }

putCPUSVN :: CPUSVN -> Put
putCPUSVN (CPUSVN cpusvn) = put cpusvn

getBigInteger_le :: Int -> Get Integer
getBigInteger_le c | c <= 0    = return 0
                   | otherwise = do
                       w  <- fmap fromIntegral getWord8
                       w' <- getBigInteger_le (c-1)
                       return $! (w' `shiftL` 8) + w

getBigInteger_be :: Int -> Get Integer
getBigInteger_be c | c <= 0    = return 0
                   | otherwise = do
                       w  <- fmap fromIntegral getWord8
                       w' <- getBigInteger_be (c-1)
                       return $! (w `shiftL` ((c-1)*8)) + w'


getEInitToken :: Get EInitToken
getEInitToken = do
  dbg        <- fmap (\x -> testBit x 0) getWord32le
  res_1      <- getLazyByteString 44
  attr       <- getAttributes
  mrenclave  <- getLazyByteString 32
  res_2      <- getLazyByteString 32
  mrsigner   <- getLazyByteString 32
  res_3      <- getLazyByteString 32
  cpusvn     <- getCPUSVN
  le_prdid   <- getWord16le
  le_isv_svn <- getWord16le
  res_4      <- getLazyByteString 24
  miscMask   <- getWord32le
  attrmask   <- getAttributes
  keyid      <- getLazyByteString 32
  mac        <- getLazyByteString 16
  return $! EInitToken
    {
      eitDebug                = dbg
    , eitReserved_byte4_47    = res_1
    , eitAttributes           = attr
    , eitMrEnclave            = mrenclave
    , eitReserved_byte96_127  = res_2
    , eitMrSigner             = mrsigner
    , eitReserved_byte160_191 = res_3
    , eitCpuSvnLe             = cpusvn
    , eitIsvProdIdLe          = le_prdid
    , eitIsvSvnLe             = le_isv_svn
    , eitReserved_byte212_235 = res_4
    , eitMaskedMiscSelectLe   = miscMask
    , eitMaskedAttributes     = attrmask
    , eitKeyId                = keyid
    , eitMAC                  = mac
    }

parseEInitToken :: L.ByteString -> EInitToken
parseEInitToken = runGet getEInitToken

getXFRM :: Get XFRM
getXFRM = do
  w <- getWord64le
  case w .&. 0x3 of
    0x3  -> return $ XFRM True  w  (w `shiftR` 2 > 0)
    _    -> return $ XFRM False 0x0 False

putXFRM :: XFRM -> Put
putXFRM x =
  case xfrmEnabled x of
    False -> putPadBytes 8 0x0
    True  ->
      case xfrmHasXSave x of
        True  -> (putWord64be . xfrmXCR0) x
        False ->
          do
            put (0xc0 :: Word8)
            putPadBytes 7 0x0

metadataMagic :: Word64
metadataMagic = 0x86A80294635D0E4C

makeMetaVersion :: Word32 -- major version
                -> Word32 -- minjor version
                -> Word64
makeMetaVersion maj minor =
  let
    m = fromIntegral maj :: Word64
    m' = fromIntegral minor :: Word64
  in
    (m `shiftL` 32) .|. m'

breakMetaVersion :: Word64 -> (Word32, Word32)
breakMetaVersion w =
  (fromIntegral (w `shiftR` 32),
   fromIntegral w)

metaVerStr :: Word64 -> String
metaVerStr w =
  case breakMetaVersion w of
    (a,b) -> printf "(%u, %u)" a b

validMetaVersion :: [Word64]
validMetaVersion = [
  makeMetaVersion 2 4
  , makeMetaVersion 2 3
  , makeMetaVersion 2 2
  , makeMetaVersion 2 1
  , makeMetaVersion 1 4
  , makeMetaVersion 1 3
  ]



getSGXDate :: Get SigStructDate
getSGXDate = do
  date <- getWord32le
  return $! getBytesToDate date

sgxKeySize :: Int
sgxKeySize = 384

getSigStruct :: Get SigStruct
getSigStruct = do
  ss1        <- getBigInteger_be 12
  unless (ss1 == fromSSHeader ssHeaderVal1) $
    fail $ printf "Invalid SigStruct Header1 value: \n%x\bexptected:%x"
                  ss1 (fromSSHeader ssHeaderVal1)
  dbg        <- getWord32le
  vendor     <- getWord32be
  date       <- getSGXDate
  ss2        <- getBigInteger_be 16
  unless (ss2 == fromSSHeader ssHeaderVal2) $
    fail $ printf "Invalid SigStruct Header2 value: \n%x\bexptected:%x"
                  ss2 (fromSSHeader ssHeaderVal2)
  hwver      <- getWord32le
  skip 84
  modulus    <- getBigInteger_le sgxKeySize
  expo       <- getWord32le
  sig        <- getBigInteger_le sgxKeySize
  misc_sel   <- getMiscSelect
  misc_mask  <- getMiscSelect
  skip 20
  ssAttr     <- getAttributes
  ssAttrMask <- getAttributes
  ehash      <- getByteString 32
  skip 32
  isvPrdId   <- getWord16le
  isvSvn     <- getWord16le
  skip 12
  q1         <- getBigInteger_le sgxKeySize
  q2         <- getBigInteger_le sgxKeySize

  return $! SigStruct {
    ssHeader1     = SSHeader ss1
    , ssIsDebug   = dbg
    , ssVendor    = if vendor == 0
                    then SSVendorOther
                    else SSVendorIntel
    , ssBuildDate              = date
    , ssHeader2                = SSHeader ss2
    , ssSwDefined              = hwver
    , ssReserved_byte44_127    = L.empty
    , ssModulus                = modulus
    , ssExponent               = expo
    , ssSignature              = sig
    , ssMiscSelect             = misc_sel
    , ssMiscMask               = misc_mask
    , ssReserved_byte908_927   = L.empty
    , ssAttributes             = ssAttr
    , ssAttributesMask         = ssAttrMask
    , ssEnclaveHash            = L.fromChunks [ehash]
    , ssReserved_byte992_1023  = L.empty
    , ssIsvProdId              = isvPrdId
    , ssIsvSvn                 = isvSvn
    , ssReserved_byte1028_1039 = L.empty
    , ssQ1                     = q1
    , ssQ2                     = q2
    }


getDataDirectory :: Get DataDirectory
getDataDirectory = do
  off  <- getWord32le
  dirSz <- getWord32le
  return $! DataDirectory
    {
      ddOffset = off
    , ddSize   = dirSz
    }

getDataDirectories :: Int -> Get [DataDirectory]
getDataDirectories count
  | count <= 0 = return []
  | otherwise  = getDDs' count []
  where
    getDDs' :: Int -> [DataDirectory] -> Get [DataDirectory]
    getDDs' 0 dd = return $! reverse dd
    getDDs' c dd = getDataDirectory >>=
      \this -> getDDs' (c-1) $! (this : dd)

putMetadata :: EnclaveMetadata -> Put
putMetadata = undefined

ddCount :: Int
ddCount = 2

ddPatchIndex :: Int
ddPatchIndex = 0

ddLayoutIndex ::Int
ddLayoutIndex = 1

getPatch :: Get PatchEntry
getPatch = do
  dest <- getWord64le
  dsrc <- getWord32le
  psz  <- getWord32le
  skip 16 -- four 32-bit ints reserved
  return $! PatchEntry
    {
      patchDest   = dest
    , patchSource = dsrc
    , patchSize   = psz
    , patchData   = B.empty
    }

getLayout :: Get LayoutEntry
getLayout = do
  gid  <- fmap (toEnum . fromIntegral) getWord16le
  case isGroupId gid of
    True -> do
      lCount <- getWord16le
      lTimes <- getWord32le
      lStep  <- getWord64le
      skip 16
      return $! LayoutGroup
        {
          lgrpID = gid
        , lgrpEntryCount = lCount
        , lgrpLoadTimes = lTimes
        , lgrpLoadStep = lStep
        , lgrpReserved = []
        }

    False -> do
      lops      <- fmap extractFlags getWord16le
      lpCount   <- getWord32le
      lpRVA     <- getWord64le
      lpContSz  <- getWord32le
      lpContOff <- getWord32le
      perm      <- getWord64le
      return $! LayoutEntry
        {
          lentryID = gid
        , lentryOps = lops
        , lentryPageCount = lpCount
        , lentryRVA = lpRVA
        , lentryContent = B.empty
        , lentryContentSz = lpContSz
        , lentryContentOff = lpContOff
        , lentryPermFlags = extractFlags (perm .&. 0xff9f) -- bit 6-7 zero
        }

getPatches :: Get [PatchEntry]
getPatches = do
  empty <- isEmpty
  if empty
    then return []
    else do
    p  <- getPatch
    p' <- getPatches
    return $! (p : p')

getLayouts :: Get [LayoutEntry]
getLayouts = do
  empty <- isEmpty
  if empty
    then return []
    else do
    l  <- getLayout
    l' <- getLayouts
    return $! (l : l')


getMetadata :: Get EnclaveMetadata
getMetadata = do
  magic       <- getWord64le
  unless (metadataMagic == magic) $
    fail $ "Invalid metadata magic " ++
    (printf "0x%.16x" magic)
  ver         <- getWord64le
  unless (ver `elem` validMetaVersion) $
    fail $ "Unsupported metadata version " ++
    metaVerStr ver
  metaSz      <- getWord32le
  tcsPolicy   <- getWord32le
  ssaFrameSz  <- getWord32le
  maxSaveSz   <- getWord32le
  desiredMisc <- getWord32le
  tcsMinPool  <- getWord32le
  enclaveSz   <- getWord64le
  attr        <- getAttributes
  css         <- getSigStruct
  dd          <- getDataDirectories ddCount
  return $! EnclaveMetadata
    {
      metaMagicNum       = magic
    , metaVersion        = ver
    , metaSize           = metaSz
    , metaTCSPolicy      = tcsPolicy
    , metaSSAFrameSize   = ssaFrameSz
    , metaMaxSaveSize    = maxSaveSz
    , metaDesiredMiscSel = desiredMisc
    , metaTCSMinPool     = tcsMinPool
    , metaEnclaveSize    = enclaveSz
    , metaAttributes     = attr
    , metaEnclaveCSS     = css
    , metaDataDirectory  = dd
    , metaPatches        = []
    , metaLayouts        = []
    }


putSecInfo :: SecInfo -> Put
putSecInfo (SecInfo perm) = do
  putWord64le flagWords
  replicateM_ 7 $! putWord64le 0
    where
      flagWords :: Word64
      flagWords = encodeFlags perm

putTCSFlags :: TCSFlags -> Put
putTCSFlags (TCSFlags debug _) =
  if debug
  then putWord64le 1
  else putWord64le 0

getTCSFlags :: Get TCSFlags
getTCSFlags = do
  w <- getWord64le
  return $! TCSFlags {
    tcsFlagsDebugOptIn = w /= 0
    , tcsFlagsReserved_bit1_63 = 0
    }


putTCS :: TCS -> Put
putTCS tcs = do
  putWord64le 0
  putTCSFlags (tcsFlags tcs)
  putWord64le (tcsOSSA tcs)
  putWord32le (tcsCSSA tcs)
  putWord32le (tcsNSSA tcs)
  putWord64le (tcsOentry tcs)
  putWord64le (tcsAep tcs)
  putWord64le (tcsOFSBasSgx tcs)
  putWord64le (tcsOGSBasSgx tcs)
  putWord32le (tcsFSLimit tcs)
  putWord32le (tcsGSLimit tcs)
--  putByteString $ B.replicate 4024 0


getTCS :: Get TCS
getTCS = do
  res    <- getWord64le
  tflags <- getTCSFlags
  tossa  <- getWord64le
  tcssa  <- getWord32le
  tnssa  <- getWord32le
  toentry <- getWord64le
  taep    <- getWord64le
  tfsbase <- getWord64le
  tgsbase <- getWord64le
  tfslimit <- getWord32le
  tgslimit <- getWord32le
--  bs       <- getByteString 4024
  return $! TCS {
    tcsReserved_byte0_7 = res
    , tcsFlags = tflags
    , tcsOSSA = tossa
    , tcsCSSA = tcssa
    , tcsNSSA = tnssa
    , tcsOentry = toentry
    , tcsAep = taep
    , tcsOFSBasSgx = tfsbase
    , tcsOGSBasSgx = tgsbase
    , tcsFSLimit   = tfslimit
    , tcsGSLimit   = tgslimit
--    , tcsReserved_byte72_4095 = bs
    }
