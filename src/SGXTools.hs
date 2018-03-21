module Main where

import System.Posix.Terminal (queryTerminal)
import System.Posix.IO (stdOutput)
import SGXTools.Types
import SGXTools.Utils
import SGXTools.Marshalling
import SGXTools.IntelSignedEnclave
import SGXToolsCmdOptions
import System.IO
import System.Environment (getProgName)
import Text.PrettyPrint.ANSI.Leijen
import qualified Data.ByteString.Lazy as L
import qualified Data.ByteString      as B

showMetadata :: Bool -- show layout
             -> Bool -- show patches
             -> Bool -- show color
             -> Either SGXELFError EnclaveMetadata
             -> IO ()
showMetadata _ _ _ (Left err) = print err
showMetadata l p c (Right m) = putDoc $! ppMetadata l p c m


showMrEnclave :: B.ByteString -> IO ()
showMrEnclave mr = putDoc $!
                   (text "MRENCLAVE") <+> colon <+> (text "0x") <>
                   (text (toHexRep (L.fromChunks [mr]))) <>
                   linebreak

showLaunchToken :: Bool
                -> EInitToken
                -> IO ()
showLaunchToken c eit = putDoc $! ppEinitToken c eit


main :: IO ()
main = do
  o <- commandOptions
  case o of
    (EinitOption fn)  -> withFile fn ReadMode printEinitInfo
    (HexOptions  fn)  -> withFile fn ReadMode hexDump
    (Version     str) -> printVersion str
    (ELFInfo fn l p c) -> withFile fn ReadMode (printElfInfo l p c)
    (Measure fn)      -> withFile fn ReadMode printMrEnclave
  where
    printMrEnclave :: Handle -> IO ()
    printMrEnclave fd = do
      either showError showMrEnclave =<< fmap measureEnclave (B.hGetContents fd)

    printElfInfo   :: Bool -- Show layout
                   -> Bool -- Show Path Dit
                   -> Bool -- Disable color
                   -> Handle -- Input file handle
                   -> IO ()
    printElfInfo l p c fd = do
      t <- queryTerminal stdOutput
      d <- fmap getEnclaveMetadata (B.hGetContents fd)
      showMetadata l p (not c && t) d

    printEinitInfo :: Handle -> IO ()
    printEinitInfo fd = do
      c <- queryTerminal stdOutput
      eit <- fmap parseEInitToken (L.hGetContents fd)
      showLaunchToken c eit

    hexDump :: Handle -> IO ()
    hexDump fd = fmap toHexRep (L.hGetContents fd) >>= print

    printVersion :: String -> IO ()
    printVersion s = do
      prog <- getProgName
      putStrLn $ prog ++ " version -- " ++ s

    showError :: SGXELFError -> IO ()
    showError (SGXELFError m) = putStrLn $ "Error: " ++ m
