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
  | CSSInfo String     {- Input file    -} -- Show SigStruct info
            Bool       {- disable color -}
  | Measure String     {- input file    -} -- Recompute mrenclave
  | WLInfo  String     {- whitelist file -}
            Bool       {- disable color -}

wlInfoParser :: Parser SGXToolsOpts
wlInfoParser = WLInfo <$> strOption
  (long "wlfile"
  <> short 'i'
  <> metavar "WHITELIST .bin FILE"
  <> help "Parse Intel created White list file"
  )
  <*> switch (long "nocolor" <> short 'c')

wlInfoOpts :: ParserInfo SGXToolsOpts
wlInfoOpts = info wlInfoParser
  (progDesc "Display Whitelist Information")

cssParser :: Parser SGXToolsOpts
cssParser = CSSInfo <$> strOption
  (long "sig-struct"
  <> short 'i'
  <> metavar "SIGSTRUCT .bin FILENAME"
  <> help "Parse SIGSTRUCT File"
  )
  <*> switch (long "nocolor" <> short 'c')


cssOpts :: ParserInfo SGXToolsOpts
cssOpts = info cssParser
  (progDesc "Display contents of a CSS File")

measureParser :: Parser SGXToolsOpts
measureParser = Measure <$> strOption
  (long "enclave"
   <> short 'i'
   <> metavar "ENCLAVE .so FILENAME"
   <> help "Recompute MrEnclave"
  )


measureOpts :: ParserInfo SGXToolsOpts
measureOpts = info measureParser
  (progDesc "Recompute mrenclave")

elfInfoParser :: Parser SGXToolsOpts
elfInfoParser = ELFInfo <$> strOption
  (long "enclave"
  <> short 'i'
  <> metavar "ENCLAVE .so FILENAME"
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
  command "metaInfo" elfOpts
  <> command "sigStruct" cssOpts
  <> command "whitelist" wlInfoOpts
  <> command "measure" measureOpts
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
