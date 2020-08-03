module System.Win32.NamedPipe.Native
  ( module System.Win32.NamedPipe.Native
  , module System.Win32.NamedPipe.NativeTypes
  ) where

import Foreign (Ptr)
import System.Win32.File (LPOVERLAPPED)
import System.Win32.Types (LPCWSTR, DWORD, HANDLE, BOOL)
import System.Win32.NamedPipe.NativeTypes

-- | https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createnamedpipea
foreign import stdcall "winbase.h CreateNamedPipeW"
  c_CreateNamedPipe
    :: LPCWSTR -- lpName,
    -> DWORD  -- dwOpenMode,
    -> DWORD  -- dwPipeMode,
    -> DWORD  -- nMaxInstances,
    -> DWORD  -- nOutBufferSize,
    -> DWORD  -- nInBufferSize,
    -> DWORD  -- nDefaultTimeOut,
    -> Ptr SECURITY_ATTRIBUTES -- lpSecurityAttributes
    -> IO HANDLE

-- | https://docs.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-connectnamedpipe
foreign import stdcall "namedpipeapi.h ConnectNamedPipe"
  c_ConnectNamedPipe
    :: HANDLE -- hNamedPipe
    -> LPOVERLAPPED -- lpOverlapped
    -> IO BOOL

-- | https://docs.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-disconnectnamedpipe
foreign import stdcall "namedpipeapi.h DisconnectNamedPipe"
  c_DisconnectNamedPipe
    :: HANDLE -- hNamedPipe
    -> IO BOOL
