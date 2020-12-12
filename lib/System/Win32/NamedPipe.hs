{-# LANGUAGE LambdaCase, NamedFieldPuns #-}
{-# LANGUAGE ScopedTypeVariables #-}
module System.Win32.NamedPipe
  ( NamedPipe, handleOfPipe
  , createNamedPipe, unsafeBlockingConnectNamedPipe
  , disconnectNamedPipe, closeNamedPipe, flushPipe
  , unsafeBlockingWritePipe
  -- * Pipe operations exceptions
  , Win32ErrorCode, Win32BrokenPipe
  -- * Pipe options. Most likely you just want to use 'def' for them
  , OpenMode (..), PipeAccess (..), PipeFileFlag (..), PipeSecurity (..)
  , PipeMode (..), PipeType (..), PipeWaitMode (..), PipeRemoteMode (..)
  , PipeInstances (..)
  ) where

import Data.Bits (Bits, (.|.))
import Data.Default (Default (def))
import Data.Word (Word8)
import Data.ByteString (ByteString)
import Data.ByteString.Unsafe (unsafeUseAsCStringLen)
import Control.Exception (Exception (..), throwIO, mask)
import Control.Monad (when)
import Control.Monad.Trans.Class (lift)
import Control.Monad.Trans.Cont (ContT (..), evalContT)
import Foreign.C.String (withCWString)
import Foreign.ForeignPtr (withForeignPtr)
import Foreign.Marshal.Alloc (alloca)
import Foreign.Storable (poke)
import Foreign.Ptr (nullPtr)
import System.IO (Handle)
import System.Mem.Weak (mkWeak, addFinalizer)
import System.Win32.File (closeHandle, flushFileBuffers, win32_WriteFile)
import System.Win32.NamedPipe.Backport (hANDLEToHandle)
import System.Win32.Types (HANDLE, ErrCode, iNVALID_HANDLE_VALUE, getLastError)

import System.Win32.NamedPipe.Native
import System.Win32.NamedPipe.Security.Native (SECURITY_ATTRIBUTES (..))
import System.Win32.NamedPipe.Security (create777securityDescriptor)


-------------
-- Exceptions

data Win32ErrorCode = Win32ErrorCode String ErrCode
  deriving (Eq, Show)

instance Exception Win32ErrorCode where
  displayException (Win32ErrorCode msg code) =
    msg ++ "; error code: " ++ show code

data Win32BrokenPipe = Win32BrokenPipe
  deriving (Eq, Show)

instance Exception Win32BrokenPipe


-----------------------
-- Flags and parameters

-- | Server pipe flags about opening mode
data OpenMode = OpenMode PipeAccess PipeFileFlag PipeSecurity
  deriving (Eq, Show, Read)

instance Default OpenMode where def = OpenMode def def def

openModeFlag :: forall a. (Bits a, Num a) => OpenMode -> a
openModeFlag (OpenMode a f s) =
  let cast = fromIntegral . fromEnum
      cast :: forall b. Enum b => b -> a
  in cast a .|. cast f .|. cast s


data PipeAccess = PipeAccessDuplex -- ^ Bidirectional pipe
                | PipeAccessInbound -- ^ From client to server only
                | PipeAccessOutboud -- ^ From server to client only
  deriving (Eq, Show, Read)

instance Default PipeAccess where def = PipeAccessDuplex

instance Enum PipeAccess where
  fromEnum = \case
    PipeAccessDuplex -> 0x3
    PipeAccessInbound -> 0x1
    PipeAccessOutboud -> 0x2
  toEnum = \case
    0x3 -> PipeAccessDuplex
    0x1 -> PipeAccessInbound
    0x2 -> PipeAccessOutboud
    _ -> error "Bad enum"


data PipeFileFlag = FileFlagFirstPipeInstance -- ^ Only the first pipe with this flag can be created
                  | FileFlagWriteThrough -- ^ Enhances speed in one edge case, see MSDN
                  | FileFlagNone
                  -- I don't support overlapped flag
  deriving (Eq, Show, Read)

instance Default PipeFileFlag where def = FileFlagNone

instance Enum PipeFileFlag where
  fromEnum = \case
    FileFlagFirstPipeInstance -> 0x80000
    FileFlagWriteThrough -> 0x80000000
    FileFlagNone -> 0
  toEnum = \case
    0x80000 -> FileFlagFirstPipeInstance
    0x80000000 -> FileFlagWriteThrough
    0 -> FileFlagNone
    _ -> error "Bad enum"
fileFlagOverlapped :: Int
fileFlagOverlapped = 0x40000000


data PipeSecurity = PipeWriteDac -- ^ Write access to pipe discretionary access control list
                  | PipeWriteOwner -- ^ Write access to pipe owner
                  | PipeAccessSystemSecurity -- ^ Write access to pipe SACL
                  | PipeSecurityNone
  deriving (Eq, Show, Read)

instance Default PipeSecurity where def = PipeSecurityNone

instance Enum PipeSecurity where
  fromEnum = \case
    PipeWriteDac -> 0x40000
    PipeWriteOwner -> 0x80000
    PipeAccessSystemSecurity -> 0x1000000
    PipeSecurityNone -> 0
  toEnum = \case
    0x40000 -> PipeWriteDac
    0x80000 -> PipeWriteOwner
    0x1000000 -> PipeAccessSystemSecurity
    0 -> PipeSecurityNone
    _ -> error "Bad enum"


-- | Pipe options that must be same for server and clients
data PipeMode = PipeMode PipeType PipeWaitMode PipeRemoteMode
  deriving (Eq, Show, Read)

instance Default PipeMode where def = PipeMode def def def

pipeModeFlag :: forall a. (Bits a, Num a) => PipeMode -> a
pipeModeFlag (PipeMode t w r) =
  let cast = fromIntegral . fromEnum
      cast :: forall b. Enum b => b -> a
  in cast t .|. cast w .|. cast r


data PipeType = PipeTypeByteByte -- ^ Write bytes, read bytes
              | PipeTypeMessageByte -- ^ Write messages, read bytes
              | PipeTypeMessage -- ^ Write and read messages
  deriving (Eq, Show, Read)

instance Default PipeType where def = PipeTypeMessage

instance Enum PipeType where
  fromEnum = \case
    PipeTypeByteByte -> 0 .|. 0
    PipeTypeMessageByte -> 0x4 .|. 0
    PipeTypeMessage -> 0x4 .|. 0x2
  toEnum = \case
   0 -> PipeTypeByteByte
   0x4 -> PipeTypeMessageByte
   0x6 -> PipeTypeMessage
   _ -> error "Bad enum"


data PipeWaitMode
  = PipeWait
  | PipeNowait -- ^ File operations return immediately. MSDN notes that this
               -- should not be used except for compatability
  deriving (Eq, Show, Read)

instance Default PipeWaitMode where def = PipeWait

instance Enum PipeWaitMode where
  fromEnum = \case
    PipeWait -> 0
    PipeNowait -> 1
  toEnum = \case
    0 -> PipeWait
    1 -> PipeNowait
    _ -> error "Bad enum"


data PipeRemoteMode = PipeAcceptRemoteClients | PipeRejectRemoteClients
  deriving (Eq, Show, Read)

instance Default PipeRemoteMode where def = PipeRejectRemoteClients

instance Enum PipeRemoteMode where
  fromEnum = \case
    PipeAcceptRemoteClients -> 0
    PipeRejectRemoteClients -> 0x8
  toEnum = \case
    0 -> PipeAcceptRemoteClients
    0x8 -> PipeRejectRemoteClients
    _ -> error "Bad enum"


-- | Amount of identical instances of a pipe created with the same name that is allowed
data PipeInstances = UnlimitedInstances | LimitedInstances Word8

instancesFlag :: Num a => PipeInstances -> a
instancesFlag = \case
  UnlimitedInstances -> fromIntegral pIPE_UNLIMITED_INSTANCES
  LimitedInstances n -> fromIntegral n


---------------------
-- Main pipe routines

data NamedPipe = NamedPipe
  { namedPipeInternal :: HANDLE
  -- | Get haskell handle to pipe OS handle. This handle sometimes writes
  -- garbage on write operations, sometimes it closes the stream on the other
  -- end. Use the blocking 'unsafeWritePipe' for a 100% of the time working
  -- writing.
  -- This handle is safe and good for reading from pipe though.
  , handleOfPipe :: Handle
  }


createNamedPipe
  :: String -- ^ Pipe name
  -> OpenMode -> PipeMode -> PipeInstances
  -> Int -- ^ Output buffer size
  -> Int -- ^ Input buffer size
  -> Int -- ^ Default timeout
  -> IO NamedPipe
createNamedPipe name openMode pipeMode instances outSize inSize timeout = mask $ \unmask -> do
  securityDescrForeignPtr <- unmask create777securityDescriptor
  winHandle <- evalContT $ do
    lpName <- ContT $ withCWString name
    securityDescr <- ContT $ withForeignPtr securityDescrForeignPtr
    securityAttrPtr <- ContT alloca
    lift . unmask $
      poke securityAttrPtr $ SECURITY_ATTRIBUTES securityDescr True -- inherit fd for forks
    --
    lift $ c_CreateNamedPipe lpName
                             (openModeFlag openMode)
                             (pipeModeFlag pipeMode)
                             (instancesFlag instances)
                             (fromIntegral outSize)
                             (fromIntegral inSize)
                             (fromIntegral timeout)
                             securityAttrPtr
  when (winHandle == iNVALID_HANDLE_VALUE) . unmask $ do
    errcode <- getLastError
    throwIO $ Win32ErrorCode "Bad handle created" errcode
  hsHandle <- hANDLEToHandle winHandle
  addFinalizer winHandle (closeHandle winHandle)
  -- make acl stuffs live as long as the handle. I don't know if this is
  -- necessary and I can't find the answers online: none of the examples deal
  -- with pipes, they do stuff like creating entries in registry. One can make
  -- a parallel between creating an entry and creating a handle, but i don't
  -- know
  _ <- mkWeak winHandle securityDescrForeignPtr Nothing
  pure $ NamedPipe winHandle hsHandle


-- | Get the client of the named pipe. Blocks the thread until client is found.
unsafeBlockingConnectNamedPipe :: NamedPipe -> IO ()
unsafeBlockingConnectNamedPipe NamedPipe {namedPipeInternal} = do
  r <- c_ConnectNamedPipe namedPipeInternal nullPtr
  if r
    then pure ()
    else do
      errcode <- getLastError
      if errcode == eRROR_PIPE_CONNECTED
        then pure ()
        else throwIO $ Win32ErrorCode "Couldn't connect named pipe" errcode

-- | Disconnect the client from the named pipe
disconnectNamedPipe :: NamedPipe -> IO ()
disconnectNamedPipe NamedPipe {namedPipeInternal} = do
  flushFileBuffers namedPipeInternal
  r <- c_DisconnectNamedPipe namedPipeInternal
  if r
    then pure ()
    else getLastError >>= throwIO . Win32ErrorCode "Couldn't disconnect named pipe"

-- | Close the pipe immediately, without waiting for garbage collection
closeNamedPipe :: NamedPipe -> IO ()
closeNamedPipe NamedPipe {} =
  -- this just throws errors everytime, so just let the handle dangle
  -- hClose handleOfPipe
  pure ()

flushPipe :: NamedPipe -> IO ()
flushPipe NamedPipe {namedPipeInternal} =
  flushFileBuffers namedPipeInternal

-- | Write data into pipe. Blocks the thread until the writing completes
unsafeBlockingWritePipe :: NamedPipe -> ByteString -> IO ()
unsafeBlockingWritePipe NamedPipe {namedPipeInternal} text =
  unsafeUseAsCStringLen text $ \ (ptr, len) -> do
    let len' = fromIntegral len
    written <- win32_WriteFile namedPipeInternal ptr len' Nothing
    if written == 0 -- or idk what to check
      then do
        errcode <- getLastError
        if errcode == eRROR_BROKEN_PIPE
        then throwIO Win32BrokenPipe
        else throwIO $ Win32ErrorCode "Couldn't disconnect named pipe" errcode
      else pure ()
