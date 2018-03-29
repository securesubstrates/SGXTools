module SGXTools.Utils (
  toHexRep            -- Show ByteString as Hex string
  , formatKVPDoc
  , keyColor
  , boldColor
  , embed
  , tabWidth
  , show2Doc
  , hexyNumDoc
  , dexyNumDoc
  , toBinaryRep       -- Show ByteString as binary string
  , integerToBSle     -- convert Integer into a little endian ByteString
  , integerToBSbe     -- convert Integer into a big endian ByteString
  , leBSToInteger     -- convert ByteString encoded as little endian in Integer
  , beBSToInteger     -- convert ByteString encoded as bin endian into Integer
  ) where

import Text.Printf     (printf, PrintfArg)
import Data.Bits       (unsafeShiftL, unsafeShiftR, (.|.) , (.&.))
import Data.Word       (Word8)
import Data.Foldable   (foldr')
import           Text.PrettyPrint.ANSI.Leijen
import qualified Data.ByteString.Lazy as L
import qualified Data.ByteString      as B

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

leBSToInteger :: B.ByteString -> Integer
leBSToInteger = foldr' (\x y -> (y `unsafeShiftL` 8) .|. (fromIntegral x)) 0x0 . B.unpack

beBSToInteger :: B.ByteString -> Integer
beBSToInteger = foldr' (\x y -> (y `unsafeShiftL` 8) .|. (fromIntegral x)) 0x0 . reverse . B.unpack

integer2word8 :: [Word8] -> Integer -> [Word8]
integer2word8 x 0 = x
integer2word8 x y = integer2word8  ((:) (fromIntegral $! 0xFF .&. y)  x) $! (y `unsafeShiftR` 8)


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

show2Doc :: (Show a) => a -> Doc
show2Doc x = text $! show x

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
    max_key_len = foldr' lenMax 0 xs
    paddedStr (key, value) = (fill max_key_len ((keyColor c . text) key)) <+>
                             colon <+> value
    innerDoc =
      foldr' (\(k,v) ->
                \y -> paddedStr (k, v) <> linebreak <> y) empty xs
  in
    lbrace                <>
    linebreak             <>
    indent 2 innerDoc     <>
    indent (-2) linebreak <>
    rbrace

hexyNumDoc :: (Integral a, Show a, PrintfArg a)
           => a
           -> Doc
hexyNumDoc num =
  let
    hNum :: Doc
    hNum = text $! (printf "0x%x" num :: String)

    dNum :: Doc
    dNum = text $! show num
  in  hNum <+> parens dNum

dexyNumDoc :: (Integral a, Show a, PrintfArg a)
           => a
           -> Doc
dexyNumDoc num =
  let
    hNum :: Doc
    hNum = text $! (printf "0x%x" num :: String)

    dNum :: Doc
    dNum = text $! show num
  in dNum <+> parens hNum


tabWidth :: Int
tabWidth = 2

embed :: Doc -> Doc
embed d = linebreak <> indent tabWidth d
