{-# LANGUAGE OverloadedStrings #-}
module Main where

import Control.Concurrent (forkIO)
import Data.ByteString.Char8 (hGetSome, putStrLn, pack)
import Data.Default (def)
import Data.Monoid ((<>))

import Prelude hiding (putStrLn)
import System.Win32.NamedPipe


main :: IO ()
main = do
    times 3 $ \n -> do
        putStrLn "- creating pipe"
        let mode = PipeMode PipeTypeMessage PipeWait PipeRejectRemoteClients
        pipe <- createNamedPipe "\\\\.\\pipe\\mynamedpipe2" def mode UnlimitedInstances 512 512 0
        putStrLn "- connecting pipe"
        connectNamedPipe pipe
        putStrLn "- forking"
        _ <- forkIO $ servePipe n pipe
        pure ()
    putStrLn "- Exiting"

servePipe :: Integer -> NamedPipe -> IO ()
servePipe number pipe = do
    let n = pack . show $ number
    let handle = handleOfPipe pipe
    putStrLn $ n <> " Waiting for pipe message"
    message <- hGetSome handle 512
    putStrLn $ n <> " got message: " <> message
    unsafeWritePipe pipe $ "Ok " <> n
    putStrLn $ n <> " put message back"
    disconnectNamedPipe pipe
    putStrLn $ n <> " disconnect pipe"
    closeNamedPipe pipe
    putStrLn $ n <> " close pipe"


times :: Monad m => Integer -> (Integer -> m ()) -> m ()
times n a = times' 0 where
    times' i | i == n     = pure ()
             | otherwise  = a i >> times' (i + 1)
