{-# LANGUAGE CPP #-}
-- | Currently backports two things from two modules:
-- 1. 'hANDLEToHandle' from System.Win32.Types
-- 2. 'OVERLAPPED' from System.Win32.File
module System.Win32.NamedPipe.Backport
  ( hANDLEToHandle
  , OVERLAPPED (..), LPOVERLAPPED
  ) where

#if MIN_VERSION_Win32(2,6,0)
import System.Win32.File (OVERLAPPED (..))
import System.Win32.Types (hANDLEToHandle)
#else


import Foreign.Storable (Storable (..))
import Foreign.C.Types (CIntPtr (..), CInt (..))
import Foreign.Ptr (Ptr, ptrToIntPtr)
import GHC.IO.Handle.FD (fdToHandle)
import System.Win32.Types (HANDLE, ULONG_PTR)
import System.IO (Handle)

#if defined(__IO_MANAGER_WINIO__)
import GHC.IO.SubSystem ((<!>))
import GHC.IO.Handle.Windows
import GHC.IO.Windows.Handle (fromHANDLE, Io(), NativeHandle(),
                              handleToMode, optimizeFileAccess)
import qualified GHC.Event.Windows as Mgr
import GHC.IO.Device (IODeviceType(..))
#endif

-- | Create a Haskell 'Handle' from a Windows 'HANDLE'.
--
-- Beware that this function allocates a new file descriptor. A consequence of
-- this is that calling 'hANDLEToHandle' on the standard Windows handles will
-- not give you 'IO.stdin', 'IO.stdout', or 'IO.stderr'. For example, if you
-- run this code:
--
-- @
-- import Graphics.Win32.Misc
-- stdoutHANDLE <- getStdHandle sTD_OUTPUT_HANDLE
-- stdout2 <- 'hANDLEToHandle' stdoutHANDLE
-- @
--
-- Then although you can use @stdout2@ to write to standard output, it is not
-- the case that @'IO.stdout' == stdout2@.
hANDLEToHandle :: HANDLE -> IO Handle
hANDLEToHandle handle = posix
#if defined(__IO_MANAGER_WINIO__)
     <!> native
#endif
  where
#if defined(__IO_MANAGER_WINIO__)
    native = do
      -- Attach the handle to the I/O manager's CompletionPort.  This allows the
      -- I/O manager to service requests for this Handle.
      Mgr.associateHandle' handle
      optimizeFileAccess handle
      let hwnd = fromHANDLE handle :: Io NativeHandle
      -- Not sure if I need to use devType here..
      mode <- handleToMode handle
      mkHandleFromHANDLE hwnd Stream ("hwnd:" ++ show handle) mode Nothing
#endif
    posix = _open_osfhandle (fromIntegral (ptrToIntPtr handle))
                            (32768) >>= fdToHandle

foreign import ccall "_open_osfhandle"
  _open_osfhandle :: CIntPtr -> CInt -> IO CInt


data OVERLAPPED
  = OVERLAPPED { ovl_internal     :: ULONG_PTR
               , ovl_internalHigh :: ULONG_PTR
               , ovl_offset       :: DWORD
               , ovl_offsetHigh   :: DWORD
               , ovl_hEvent       :: HANDLE
               } deriving (Show)

instance Storable OVERLAPPED where
  sizeOf = const ((32))
  alignment _ = 8
  poke buf ad = do
    ((\hsc_ptr -> pokeByteOff hsc_ptr 0)) buf (ovl_internal     ad)
    ((\hsc_ptr -> pokeByteOff hsc_ptr 8)) buf (ovl_internalHigh ad)
    ((\hsc_ptr -> pokeByteOff hsc_ptr 16)) buf (ovl_offset       ad)
    ((\hsc_ptr -> pokeByteOff hsc_ptr 20)) buf (ovl_offsetHigh   ad)
    ((\hsc_ptr -> pokeByteOff hsc_ptr 24)) buf (ovl_hEvent       ad)

  peek buf = do
    intnl      <- ((\hsc_ptr -> peekByteOff hsc_ptr 0)) buf
    intnl_high <- ((\hsc_ptr -> peekByteOff hsc_ptr 8)) buf
    off        <- ((\hsc_ptr -> peekByteOff hsc_ptr 16)) buf
    off_high   <- ((\hsc_ptr -> peekByteOff hsc_ptr 20)) buf
    hevnt      <- ((\hsc_ptr -> peekByteOff hsc_ptr 24)) buf
    return $ OVERLAPPED intnl intnl_high off off_high hevnt

type LPOVERLAPPED = Ptr OVERLAPPED


#endif
-- endif MIN_VERSION_Win32(2,6,0)
