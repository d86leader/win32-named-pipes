{-# LANGUAGE OverloadedStrings #-}
module Main where

import Foreign (alloca, poke, castPtr)
import Foreign.ForeignPtr (withForeignPtr)
import System.Win32.NamedPipe.Security.Native (SECURITY_ATTRIBUTES (..))
import System.Win32.NamedPipe.Security (create777securityDescriptor)
import System.Win32.File (createFile, closeHandle)

main :: IO ()
main = do
    secDescFptr <- create777securityDescriptor
    withForeignPtr secDescFptr $ \secDesc ->
      alloca $ \lpSecAttrs -> do
        let secAttrs = SECURITY_ATTRIBUTES secDesc True
        poke lpSecAttrs secAttrs
        h <- createFile "./testfile" 0 0 (Just $ castPtr lpSecAttrs) 2 0x80 Nothing
        closeHandle h
