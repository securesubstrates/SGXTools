module SGXTools.Utils (
  toHexRep            -- Show ByteString as Hex string
  , toBinaryRep       -- Show ByteString as binary string
  , integerToBSle     -- convert Integer into a little endian ByteString
  , integerToBSbe     -- convert Integer into a big endian ByteString
  , leBSToInteger     -- convert ByteString encoded as little endian in Integer
  , beBSToInteger     -- convert ByteString encoded as bin endian into Integer
  ) where

import Text.Printf     (printf)
import Data.Bits       (unsafeShiftL, unsafeShiftR, (.|.) , (.&.))
import Data.Word       (Word8)
import Data.Foldable   (foldr')
import qualified Data.ByteString.Lazy as L

toHexRep :: L.ByteString -> String
toHexRep bs = concatMap toHexStr (L.unpack bs)
  where
    toHexStr :: Word8 -> String
    toHexStr = printf "%.2x"

toBinaryRep :: L.ByteString -> String
toBinaryRep bs = concatMap toBinStr (L.unpack bs)
  where
    toBinStr :: Word8 -> String
    toBinStr x = [bitVal x (7-i) | i <- [0..7]]

    bitVal :: Word8 -> Int -> Char
    bitVal x l = let val  = (x `unsafeShiftR` l) .&. 0x1
                 in if val == 1
                    then '1'
                    else '0'

-- This is not the most efficient implementation, but it's easy
-- to understand and use
integerToBSle :: Integer -> L.ByteString
integerToBSle = L.pack . reverse . integer2word8 []

integerToBSbe :: Integer -> L.ByteString
integerToBSbe = L.pack . integer2word8 []

leBSToInteger :: L.ByteString -> Integer
leBSToInteger = foldr' (\x -> \y -> (y `unsafeShiftL` 8) .|. (fromIntegral x)) 0x0 . L.unpack

beBSToInteger :: L.ByteString -> Integer
beBSToInteger = foldr' (\x -> \y -> (y `unsafeShiftL` 8) .|. (fromIntegral x)) 0x0 . reverse . L.unpack

integer2word8 :: [Word8] -> Integer -> [Word8]
integer2word8 x 0 = x
integer2word8 x y = integer2word8  ((:) (fromIntegral $! 0xFF .&. y)  x) $! (y `unsafeShiftR` 8)
