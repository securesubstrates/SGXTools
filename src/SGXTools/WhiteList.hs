{-# LANGUAGE BangPatterns #-}

module SGXTools.WhiteList(
  parseWhiteList
  , parseIntelWhiteList
  , SGXWhiteListError(..)
  , WhiteList(..)
  , WhiteListEntry (..)
  , WLCertChainIntel(..)
  , WLProviderCertIntel(..)
  , WLCertIntel(..)
  )where

import qualified Data.ByteString         as B
import qualified Data.ByteString.Lazy    as L
import qualified Data.Binary.Get         as G
import qualified Crypto.PubKey.ECC.Types as EC
import qualified Crypto.PubKey.RSA       as RSA
import qualified Crypto.PubKey.ECC.ECDSA as ECDSA

import           Data.Word
import           Data.Bits
import           Data.Foldable (foldr')

data SGXWhiteListError =
  SGXWhiteListError String deriving (Show)

fromLEBytes :: [Word8] -> Integer
fromLEBytes lst =
  foldr' (\x !y ->
             (y `shiftL` 8) .|. fromIntegral x) 0 lst
{-# INLINE fromLEBytes #-}

fromBEBytes :: [Word8] -> Integer
fromBEBytes = fromLEBytes . reverse

g_wl_root_pubkey_x :: Integer
g_wl_root_pubkey_x = fromLEBytes [ -- see linux-sdk/psw/ae/data/constants/linux/wl_pub.hh
  0x29, 0x39, 0x1e, 0x9b
  , 0xcb, 0x86, 0xd6, 0xeb
  , 0x3c, 0x17, 0x91, 0xc8
  , 0x8f, 0xc9, 0x5f, 0x8c
  , 0xee, 0x0c, 0x1c, 0x75
  , 0x60, 0x9c, 0x16, 0xc2
  , 0x18, 0x6d, 0x67, 0x31
  , 0x45, 0x5c, 0x36, 0xa9
  ]

g_wl_root_pubkey_y :: Integer
g_wl_root_pubkey_y = fromLEBytes [
  0x5f, 0x09, 0x83, 0x0d
  , 0xe1, 0x22, 0xda, 0xe4
  , 0xed, 0x97, 0x54, 0xe6
  , 0xfe, 0xe2, 0xcc, 0x93
  , 0x5e, 0x05, 0x99, 0x84
  , 0xc9, 0x4f, 0x44, 0x24
  , 0x7a, 0x28, 0xcf, 0x81
  , 0xca, 0x11, 0x7e, 0xb6
  ]

g_wl_root_pubkey :: EC.Point
g_wl_root_pubkey = EC.Point
  g_wl_root_pubkey_x g_wl_root_pubkey_y


data WLCertChainIntel = WLCertChainIntel {
  wlcProviderCert    :: !WLProviderCertIntel
  , wlcCert          :: !WLCertIntel
  , wlcLEBakedPubKey :: !EC.Point
  } deriving (Show)


data WLProviderCertIntel = WLProviderCertIntel {
  wlpVersion      :: !Word16 -- Cert format version. Valid version is 1
  , wlpCertType   :: !Word16 -- Type of signer
  , wlpProviderId :: !Word16 -- ID assigned by the White List Root CA.
  , wlpRootID     :: !Word16 -- White List Root CA key
  , wlpPubKey     :: !EC.Point   -- Provider's public key
  , wlpSignature  :: !ECDSA.Signature
  }deriving(Show)


data WLCertIntel = WLCertIntel {
  wlCertVersion      :: !Word16
  , wlCertType       :: !Word16
  , wlCertProviderId :: !Word16 -- Enclave Signing Key White List Provider ID
  , wlCertLEProdId   :: !Word16 -- Launch Enclave ProdID the White List Cert applies to. Linux LE-ProdID = 0x20
  , wlCertSignKeyVer :: !Word32
  , wlCertCount      :: !Word32
  , wlCertMrSigners  :: [B.ByteString] -- list of mrsigners
  } deriving(Show)


data WhiteList = WhiteList {
    wlFileVersion :: !Word16
  , wlVersion     :: !Word32
  , wlCount       :: !Word16
  , wlPk          :: !RSA.PublicKey
  , wlEntries     :: [WhiteListEntry]
  }deriving(Show)


data WhiteListEntry = WhiteListEntry {
  wleProvisionKey     :: !Word8
  , wleMatchMrEnclave :: !Word8
  , wleMrEnclave      :: B.ByteString
  , wleMrSigner       :: B.ByteString
  }deriving(Show)


getWLCertChainIntel :: G.Get WLCertChainIntel
getWLCertChainIntel = do
  !prov  <- getWLProviderCertIntel
  !certs <- getWLCertIntel
  return $! WLCertChainIntel{
    wlcProviderCert = prov
    , wlcCert = certs
    , wlcLEBakedPubKey = g_wl_root_pubkey
    }


getPoint :: G.Get EC.Point
getPoint = do
  px <- G.getByteString 32
  py <- G.getByteString 32
  let
    pxInt = fromBEBytes $ B.unpack px
    pyInt = fromBEBytes $ B.unpack py
  return $! EC.Point pxInt pyInt

getECCSig :: G.Get ECDSA.Signature
getECCSig = do
  (EC.Point x y) <- getPoint
  return $! ECDSA.Signature x y

getWLProviderCertIntel :: G.Get WLProviderCertIntel
getWLProviderCertIntel = do
  !wlpVer   <- G.getWord16be
  !certType <- G.getWord16be
  !provId   <- G.getWord16be
  !rootId   <- G.getWord16be
  !point    <- getPoint
  !sig      <- getECCSig
  return $! WLProviderCertIntel {
    wlpVersion      = wlpVer
    , wlpCertType   = certType
    , wlpProviderId = provId
    , wlpRootID     = rootId
    , wlpPubKey     = point
    , wlpSignature  = sig
    }


getMrSigners :: G.Get [B.ByteString]
getMrSigners = do
  consumed <- G.isEmpty
  if consumed
    then return []
    else do
      signer <- G.getByteString 32
      rest   <- getMrSigners
      return $! (signer : rest)


getWLCertIntel :: G.Get WLCertIntel
getWLCertIntel = do
  certVer  <- G.getWord16be
  certType <- G.getWord16be
  provId   <- G.getWord16be
  prodId   <- G.getWord16be
  keyVer   <- G.getWord32be
  count    <- G.getWord32be
  signers  <- getMrSigners
  return $! WLCertIntel {
    wlCertVersion      = certVer
    , wlCertType       = certType
    , wlCertProviderId = provId
    , wlCertLEProdId   = prodId
    , wlCertSignKeyVer = keyVer
    , wlCertCount      = count
    , wlCertMrSigners  = signers
    }


getRSAPub :: G.Get RSA.PublicKey
getRSAPub = do
  !modBs <- G.getByteString 384
  !expo  <- G.getWord32be
  return $! RSA.PublicKey {
    RSA.public_size = 384
    , RSA.public_n  = fromBEBytes $! B.unpack modBs
    , RSA.public_e  = fromIntegral expo
  }

getWhiteList :: G.Get WhiteList
getWhiteList = do
  !fVer    <- G.getWord16be
  !ver     <- G.getWord32be
  !count   <- G.getWord16be
  !pk      <- getRSAPub
  !entries <- getWLEntries
  return $! WhiteList {
    wlFileVersion = fVer
    , wlVersion = ver
    , wlCount = count
    , wlPk    = pk
    , wlEntries = entries
    }


getWLEntry :: G.Get WhiteListEntry
getWLEntry = do
  !isProvision <- G.getWord8
  !matchMrEnc  <- G.getWord8
  G.skip 6
  !mrenc       <- G.getByteString 32
  !mrsigner    <- G.getByteString 32
  return $! WhiteListEntry {
    wleProvisionKey     = isProvision
    , wleMatchMrEnclave = matchMrEnc
    , wleMrEnclave      = mrenc
    , wleMrSigner       = mrsigner
    }


getWLEntries :: G.Get [WhiteListEntry]
getWLEntries = do
  empty <- G.isEmpty
  if empty
    then return []
    else do
      !entry <- getWLEntry
      !rest  <- getWLEntries
      return (entry:rest)

parseWhiteList :: L.ByteString
               -> Either SGXWhiteListError WhiteList
parseWhiteList bs =
  case G.runGetOrFail getWhiteList bs of
    Left (_, _, e)  -> Left $! SGXWhiteListError e
    Right(_, _, wl) -> Right $! wl

parseIntelWhiteList :: L.ByteString
                    -> Either SGXWhiteListError WLCertChainIntel
parseIntelWhiteList bs =
  case G.runGetOrFail getWLCertChainIntel bs of
    Left(_, _, e)   -> Left  $! SGXWhiteListError e
    Right(_, _, wl) -> Right $! wl
