{-# LANGUAGE CPP #-}
{-# LANGUAGE OverloadedStrings #-}

module SGXTools.Marshalling where

import SGXTools.Types
import Control.Monad (unless)
import Text.Printf   (printf)
import Data.Bits
import Data.Binary
import Data.Binary.Put
import Data.Binary.Get
import qualified Data.Binary.Builder as BD
import qualified Data.ByteString.Lazy as L


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
  return $ MiscSelect (msBit .&. 0x80 == 0x80) 0x00

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
  xf       <- get
  return Attributes {
    attrInit                = testBit w 0
    , attrDebug             = testBit w 1
    , attrMode64Bit         = testBit w 2
    , attrReserved_bit3     = False
    , attrProvisionKey      = testBit w 4
    , attrEinitTokenKey     = testBit w 5
    , attrReserved_bit6_63  = L.take 7 $ L.repeat 0x0
    , attrXFRM              = xf
    }


putAttributes  :: Attributes -> Put
putAttributes attr = do
  put topByte
  putPadBytes 7 0x0
  put (attrXFRM attr)
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
  makeMetaVersion 2 2
  , makeMetaVersion 2 1
  , makeMetaVersion 1 4
  , makeMetaVersion 1 3
  ]


getSGXDate :: Get SigStructDate
getSGXDate = do
  _ <- getWord32be
  return $! SSDate
    {
      ssYear = Year 0 0 0 0
    , ssMonth = Jan
    , ssDay   = Day 1
    }

sgxKeySize :: Int
sgxKeySize = 384

getSigStruct :: Get SigStruct
getSigStruct = do
  ss1        <- getBigInteger_be 12
  isDebug    <- getWord32le
  vendor     <- getWord32le
  date       <- getSGXDate
  ss2        <- getBigInteger_be 16
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
    , ssIsDebug   = isDebug == 0x80000000
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

putMetadata :: EnclaveMetadata -> Put
putMetadata = undefined

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
  css         <- getSigStruct
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
    , metaEnclaveCSS     = css
    , metaDataDirectory  = []
    , metaPatchRegion    = []
    , metaLayoutRegion   = []
    }


instance Binary EnclaveMetadata where
  get = getMetadata
  put = putMetadata

instance Binary MiscSelect where
  put  = putMiscSelect
  get  = getMiscSelect

instance Binary CPUSVN where
  get  = getCPUSVN
  put  = putCPUSVN

instance Binary Attributes where
  get = getAttributes
  put = putAttributes

instance Binary XFRM where
  get = getXFRM
  put = putXFRM

instance Binary EInitToken where
  get = getEInitToken
  put = undefined
