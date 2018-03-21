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
  | HexOptions String  {- Input file    -} -- Hexdump a file
  | EinitOption String {- Input file    -} -- Print einit token info
  | ELFInfo String     {- Input file    -} -- Show enclave metadata
            Bool       {- show layout   -}
            Bool       {- show path     -}
            Bool       {- disable color -}
  | Measure String     {- input file    -} -- Recompute mrenclave

measureParser :: Parser SGXToolsOpts
measureParser = Measure <$> strOption
  (long "enclave"
   <> short 'i'
   <> metavar "ENCLAVE .SO FILENAME"
   <> help "Recompute MrEnclave"
  )

measureOpts :: ParserInfo SGXToolsOpts
measureOpts = info measureParser
  (progDesc "Recompute mrenclave")

elfInfoParser :: Parser SGXToolsOpts
elfInfoParser = ELFInfo <$> strOption
  (long "enclave"
  <> short 'i'
  <> metavar "ENCLAVE .SO FILENAME"
  <> help "Signed enclave .so filename")
  <*> switch (long "print-layout" <> short 'l')
  <*> switch (long "print-patch" <> short 'p')
  <*> switch (long "nocolor" <> short 'c')

elfOpts :: ParserInfo SGXToolsOpts
elfOpts = info elfInfoParser
  (progDesc "Display enclave metadata layout")

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
  command "measure" measureOpts
  <> command "metaInfo" elfOpts
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
