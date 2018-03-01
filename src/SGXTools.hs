module Main where

import SGXTools.Types
import SGXTools.Utils
import SGXTools.Marshalling
import SGXTools.IntelSignedEnclave
import SGXToolsCmdOptions
import System.IO
import System.Environment (getProgName)
import qualified Data.ByteString.Lazy as L
import qualified Data.ByteString      as B

main :: IO ()
main = do
  o <- commandOptions
  case o of
    (ELFInfo     fn)  -> withFile fn ReadMode printElfInfo
    (EinitOption fn)  -> withFile fn ReadMode printEinitInfo
    (HexOptions  fn)  -> withFile fn ReadMode hexDump
    (Version     str) -> printVersion str
  where
    printElfInfo   :: Handle -> IO ()
    printElfInfo fd = fmap getEnclaveMetadata (B.hGetContents fd) >>= print

    printEinitInfo :: Handle -> IO ()
    printEinitInfo fd = fmap parseEInitToken (L.hGetContents fd) >>= print

    hexDump :: Handle -> IO ()
    hexDump fd = fmap toHexRep (L.hGetContents fd) >>= print

    printVersion :: String -> IO ()
    printVersion s = do
      prog <- getProgName
      putStrLn $ prog ++ " version -- " ++ s
