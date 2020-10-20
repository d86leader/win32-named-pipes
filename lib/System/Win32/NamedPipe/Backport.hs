{-# LANGUAGE CPP #-}
module System.Win32.NamedPipe.Backport
  ( hANDLEToHandle
  ) where

#if MIN_VERSION_Win32(2,6,0)
import System.Win32.Types (hANDLEToHandle)
#else


import Foreign.C.Types (CIntPtr (..), CInt (..))
import Foreign.Ptr (ptrToIntPtr)
import GHC.IO.Handle.FD (fdToHandle)
import System.Win32.Types (HANDLE)
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


#endif
-- endif MIN_VERSION_Win32(2,6,0)
