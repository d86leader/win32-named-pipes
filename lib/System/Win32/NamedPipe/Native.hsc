module System.Win32.NamedPipe.Native where

#include "windows.h"

import Foreign (Ptr)
import System.Win32.File (LPOVERLAPPED)
import System.Win32.Types (LPCWSTR, DWORD, HANDLE, BOOL)
import System.Win32.NamedPipe.Security.Native (SECURITY_ATTRIBUTES)

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


------------------
-- Some constants


pIPE_UNLIMITED_INSTANCES :: DWORD
pIPE_UNLIMITED_INSTANCES = #{const PIPE_UNLIMITED_INSTANCES}

eRROR_PIPE_CONNECTED :: DWORD
eRROR_PIPE_CONNECTED = #{const ERROR_PIPE_CONNECTED}

eRROR_BROKEN_PIPE :: DWORD
eRROR_BROKEN_PIPE = #{const ERROR_BROKEN_PIPE}
