module System.Win32.NamedPipe.Security
  ( create777securityDescriptor
  ) where

#include "windows.h"
#include "winnt.h"
#include "accctrl.h"

import Control.Exception (mask_)
import Control.Monad.Trans.Class (lift)
import Control.Monad.Trans.Cont (ContT (..), evalContT)
import Foreign.Marshal.Alloc (alloca, mallocBytes, finalizerFree)
import Foreign.Marshal.Array (withArray)
import Foreign.ForeignPtr (ForeignPtr, newForeignPtr, withForeignPtr)
import Foreign.Ptr (nullPtr)
import Foreign.Storable (poke, peek)
import System.Win32.Types (DWORD, failIfFalse_, failUnlessSuccess)
import System.Win32.Security (ACL, SID)

import System.Win32.NamedPipe.Security.Native


allocateAndInitializeSid :: SID_IDENTIFIER_AUTHORITY -> [DWORD] -> IO (ForeignPtr SID)
allocateAndInitializeSid identifierAuthority subAuthorities = evalContT $ do
  resultSid <- ContT alloca
  --
  topLevelIdent <- ContT alloca
  lift $ poke topLevelIdent identifierAuthority
  --
  let meaningfulSubs = fromIntegral $ length subAuthorities
  let sub0:sub1:sub2:sub3:sub4:sub5:sub6:sub7:_ = subAuthorities ++ repeat 0
  --
  lift . mask_ $ do
    -- can't have an async exception before we initialize foreign ptr
    failIfFalse_ "c_AllocateAndInitializeSid" $
      c_AllocateAndInitializeSid
        topLevelIdent
        meaningfulSubs sub0 sub1 sub2 sub3 sub4 sub5 sub6 sub7
        resultSid
    pSid <- peek resultSid
    newForeignPtr p_FreeSid pSid

setEntriesInAcl :: [EXPLICIT_ACCESS_W] -> PACL -> IO (ForeignPtr ACL)
setEntriesInAcl entries oldAcl = evalContT $ do
  let size = length entries
  pEntries <- ContT $ withArray entries
  ppAcl <- ContT alloca
  lift . mask_ $ do
    -- can't have an async exception before we initialize foreign ptr
    failUnlessSuccess "c_SetEntriesInAclW" $
      c_SetEntriesInAclW (fromIntegral size) pEntries oldAcl ppAcl
    pAcl <- peek ppAcl
    newForeignPtr p_LocalFreeAcl pAcl


create777securityDescriptor :: IO (ForeignPtr SECURITY_DESCRIPTOR)
create777securityDescriptor = evalContT $ do
  everyoneSidForeignPtr <- lift $ allocateAndInitializeSid worldSidAuthority [worldRid]
  everyoneSid <- ContT $ withForeignPtr everyoneSidForeignPtr
  let everyoneAccess = EXPLICIT_ACCESS_W
        { accessPermissions = #{const ~0} -- all rights
        , accessMode = setAccess
        , inheritance = #{const NO_INHERITANCE}
        , trustee = TRUSTEE_W
          { trusteeType = trusteeIsWellKnownGroup
          , trusteeVal = TRUSTEE_IS_SID everyoneSid
          }
        }
  aclForeignPtr <- lift $ setEntriesInAcl [everyoneAccess] nullPtr
  acl <- ContT $ withForeignPtr aclForeignPtr
  --
  descrForeignPtr <- lift . mask_ $ do
    ptr <- mallocBytes #{const SECURITY_DESCRIPTOR_MIN_LENGTH}
    newForeignPtr finalizerFree ptr
  descr <- ContT $ withForeignPtr descrForeignPtr
  lift . failIfFalse_ "c_InitializeSecurityDescriptor" $
    c_InitializeSecurityDescriptor descr #{const SECURITY_DESCRIPTOR_REVISION}
  lift . failIfFalse_ "c_SetSecurityDescriptorDacl" $
    c_SetSecurityDescriptorDacl descr True acl False
  pure descrForeignPtr
