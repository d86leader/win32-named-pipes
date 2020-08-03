module System.Win32.NamedPipe.NativeTypes where

#include "windows.h"

import Foreign (Storable (..), nullPtr)
import System.Win32.Types (DWORD)


pIPE_UNLIMITED_INSTANCES :: DWORD
pIPE_UNLIMITED_INSTANCES = #{const PIPE_UNLIMITED_INSTANCES}

eRROR_PIPE_CONNECTED :: DWORD
eRROR_PIPE_CONNECTED = #{const ERROR_PIPE_CONNECTED}

eRROR_BROKEN_PIPE :: DWORD
eRROR_BROKEN_PIPE = #{const ERROR_BROKEN_PIPE}


data SECURITY_ATTRIBUTES = SECURITY_ATTRIBUTES {inheritHandle :: Bool}

instance Storable SECURITY_ATTRIBUTES where
  alignment _ = #{alignment SECURITY_ATTRIBUTES}
  sizeOf _ = #{size SECURITY_ATTRIBUTES}
  peek ptr = SECURITY_ATTRIBUTES <$> #{peek SECURITY_ATTRIBUTES, bInheritHandle} ptr
  poke ptr s@(SECURITY_ATTRIBUTES b) = do
    #{poke SECURITY_ATTRIBUTES, nLength} ptr $ sizeOf s
    #{poke SECURITY_ATTRIBUTES, lpSecurityDescriptor} ptr nullPtr
    #{poke SECURITY_ATTRIBUTES, bInheritHandle} ptr b
