{-# LANGUAGE CPP #-}

module SGXToolsCmdOptions(
  SGXToolsOpts(..)
  , commandOptions
) where

import Options.Applicative
import Data.Semigroup ((<>))

#ifdef TOOL_VERSION
toolVersion :: String
toolVersion = TOOL_VERSION
#else
toolVersion :: String
toolVersion = "0.0.0.1"
#endif

data SGXToolsOpts = Version String
  | HexOptions {
      binFile :: String -- Hexdump a file
  }
  | EinitOption {
      einitFile :: String
  }
  | ELFInfo {
      elfFile :: String
  }

elfInfoParser :: Parser SGXToolsOpts
elfInfoParser = ELFInfo <$> strOption
  (long "enclave"
  <> short 'i'
  <> metavar "ENCLAVE .SO FILENAME"
  <> help "Signed enclave .so filename")

elfOpts :: ParserInfo SGXToolsOpts
elfOpts = info elfInfoParser
  (progDesc "Disable enclave loading layout")

versionParser :: Parser SGXToolsOpts
versionParser = pure $ Version toolVersion

versionOpts :: ParserInfo SGXToolsOpts
versionOpts = info versionParser
  (progDesc "Display Program Version")

hexParser :: Parser SGXToolsOpts
hexParser = HexOptions <$> strOption
  (long "file"
   <> short 'i'
   <> metavar "FILENAME"
   <> help "Binary filename to convert to hex"
  )

hexOpts :: ParserInfo SGXToolsOpts
hexOpts = info hexParser
  (progDesc "Convert binary file to hex")


einitParser :: Parser SGXToolsOpts
einitParser = EinitOption <$> strOption (
  long "einitfile"
  <> short 'i'
  <> metavar "EINITTOKEN file"
  <> help "EINIT token file"
  )

einitOpts :: ParserInfo SGXToolsOpts
einitOpts = info einitParser
  (progDesc "Display EINIT token information")

totalParser :: Parser SGXToolsOpts
totalParser = subparser $
  command "enclaveInfo" elfOpts
  <> command "einitInfo" einitOpts
  <> command "hexdump" hexOpts
  <> command "version" versionOpts

opts :: ParserInfo SGXToolsOpts
opts = info (totalParser <**> helper)
  (fullDesc
   <> progDesc "Tools for working with SGX data structures"
   <> header "sgxTools -- Bundle of SGX Tools"
  )

commandOptions :: IO SGXToolsOpts
commandOptions = execParser opts
