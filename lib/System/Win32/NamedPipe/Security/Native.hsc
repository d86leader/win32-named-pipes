{-# LANGUAGE RecordWildCards #-}

-- | Everything related to SECURITY_DESCRIPTOR handling
module System.Win32.NamedPipe.Security.Native
  ( module System.Win32.NamedPipe.Security.Native
  , module System.Win32.Security
  ) where

import Data.Word (Word32)
import Foreign (Storable (..), Ptr, nullPtr)
import System.Win32.Types (DWORD, BYTE, LPWSTR, ULONG)
import System.Win32.Security (SECURITY_DESCRIPTOR, PSID, PACL)

#include "windows.h"
#include "accctrl.h"


type PSECURITY_DESCRIPTOR = Ptr SECURITY_DESCRIPTOR

data SECURITY_ATTRIBUTES = SECURITY_ATTRIBUTES
  { securityDescriptor :: {-# UNPACK #-} !PSECURITY_DESCRIPTOR
  , inheritHandle :: !Bool
  }


data SID_IDENTIFIER_AUTHORITY = SID_IDENTIFIER_AUTHORITY
  { value0 :: BYTE
  , value1 :: BYTE
  , value2 :: BYTE
  , value3 :: BYTE
  , value4 :: BYTE
  , value5 :: BYTE
  }

authorityEveryone :: SID_IDENTIFIER_AUTHORITY
authorityEveryone = SID_IDENTIFIER_AUTHORITY 0 0 0 0 0 1 -- taken from winnt.h


data EXPLICIT_ACCESS_W = EXPLICIT_ACCESS_W
  { accessPermissions :: {-# UNPACK #-} !DWORD
  , accessMode :: {-# UNPACK #-} !(#{type ACCESS_MODE}) -- ^ enum
  , inheritance :: {-# UNPACK #-} !DWORD
  , trustee :: {-# UNPACK #-} !TRUSTEE_W
  }

data TRUSTEE_W = TRUSTEE_W
  -- msdn says multipleTrustee is unsupported, a shame
  { trusteeType :: {-# UNPACK #-} !(#{type TRUSTEE_TYPE}) -- ^ enum
  , trusteeVal :: TrusteeUnion -- ^ lazy and wrapped to allow undefined when peeking
  }
data TrusteeUnion
  = TRUSTEE_IS_NAME LPWSTR
  | TRUSTEE_IS_SID PSID
  -- there are two more, but fuck them

data EXPLICIT_ACCESS

--------------------------------------------------
-- Functions to create descriptors

foreign import stdcall unsafe "windows.h InitializeSecurityDescriptor"
  c_initializeSecurityDescriptor
    :: PSECURITY_DESCRIPTOR -- pSecurityDescriptor
    -> DWORD -- dwRevision
    -> IO Bool

foreign import stdcall unsafe "windows.h SetSecurityDescriptorDacl"
  c_setSecurityDescriptorDacl
    :: PSECURITY_DESCRIPTOR -- pSecurityDescriptor
    -> Bool -- bDaclPresent
    -> PACL -- pDacl
    -> Bool -- bDaclDefaulted
    -> IO Bool

foreign import stdcall unsafe "windows.h SetSecurityDescriptorGroup"
  c_setSecurityDescriptorGroup
    :: PSECURITY_DESCRIPTOR -- pSecurityDescriptor
    -> PSID -- pGroup
    -> Bool -- bGroupDefaulted
    -> IO Bool

foreign import stdcall unsafe "windows.h SetSecurityDescriptorOwner"
  c_setSecurityDescriptorOwner
    :: PSECURITY_DESCRIPTOR -- pSecurityDescriptor
    -> PSID -- pOwner
    -> Bool -- bOwnerDefaulted
    -> IO Bool

foreign import stdcall unsafe "windows.h SetSecurityDescriptorSacl"
  c_setSecurityDescriptorSacl
    :: PSECURITY_DESCRIPTOR -- pSecurityDescriptor
    -> Bool -- bSaclPresent
    -> PACL -- pSacl
    -> Bool -- bSaclDefaulted
    -> IO Bool

foreign import stdcall unsafe "windows.h AllocateAndInitializeSid"
  c_AllocateAndInitializeSid
    :: Ptr SID_IDENTIFIER_AUTHORITY -- pIdentifierAuthority
    -> BYTE -- nSubAuthorityCount
    -> DWORD -- nSubAuthority0
    -> DWORD -- nSubAuthority1
    -> DWORD -- nSubAuthority2
    -> DWORD -- nSubAuthority3
    -> DWORD -- nSubAuthority4
    -> DWORD -- nSubAuthority5
    -> DWORD -- nSubAuthority6
    -> DWORD -- nSubAuthority7
    -> PSID -- *pSid
    -> Bool

foreign import stdcall unsafe "aclapi.h SetEntriesInAclW"
  c_SetEntriesInAclW
    :: ULONG -- cCountOfExplicitEntries,
    -> Ptr EXPLICIT_ACCESS_W -- pListOfExplicitEntries,
    -> PACL -- OldAcl,
    -> PACL -- *NewAcl


---------------------
-- Storable instances

instance Storable SECURITY_ATTRIBUTES where
  alignment _ = #{alignment SECURITY_ATTRIBUTES}
  sizeOf _ = #{size SECURITY_ATTRIBUTES}
  peek ptr = SECURITY_ATTRIBUTES
    <$> #{peek SECURITY_ATTRIBUTES, lpSecurityDescriptor} ptr
    <*> #{peek SECURITY_ATTRIBUTES, bInheritHandle} ptr
  poke ptr s@(SECURITY_ATTRIBUTES d b) = do
    #{poke SECURITY_ATTRIBUTES, nLength} ptr $ sizeOf s
    #{poke SECURITY_ATTRIBUTES, lpSecurityDescriptor} ptr d
    #{poke SECURITY_ATTRIBUTES, bInheritHandle} ptr b

instance Storable SID_IDENTIFIER_AUTHORITY where
  alignment _ = #{alignment SID_IDENTIFIER_AUTHORITY}
  sizeOf _ = #{size SID_IDENTIFIER_AUTHORITY}
  peek ptr = SID_IDENTIFIER_AUTHORITY
    <$> peekByteOff ptr 0
    <*> peekByteOff ptr 1
    <*> peekByteOff ptr 2
    <*> peekByteOff ptr 3
    <*> peekByteOff ptr 4
    <*> peekByteOff ptr 5
  poke ptr SID_IDENTIFIER_AUTHORITY {..} = do
    pokeByteOff ptr 0 value0
    pokeByteOff ptr 1 value1
    pokeByteOff ptr 2 value2
    pokeByteOff ptr 3 value3
    pokeByteOff ptr 4 value4
    pokeByteOff ptr 5 value5

instance Storable EXPLICIT_ACCESS_W where
  alignment _ = #{alignment EXPLICIT_ACCESS_W}
  sizeOf _ = #{size EXPLICIT_ACCESS_W}
  peek ptr = EXPLICIT_ACCESS_W
    <$> #{peek EXPLICIT_ACCESS_W, grfAccessPermissions} ptr
    <*> #{peek EXPLICIT_ACCESS_W, grfAccessMode} ptr
    <*> #{peek EXPLICIT_ACCESS_W, grfInheritance} ptr
    <*> #{peek EXPLICIT_ACCESS_W, Trustee} ptr
  poke ptr EXPLICIT_ACCESS_W {..} = do
    #{poke EXPLICIT_ACCESS_W, grfAccessPermissions} ptr accessPermissions
    #{poke EXPLICIT_ACCESS_W, grfAccessMode} ptr accessMode
    #{poke EXPLICIT_ACCESS_W, grfInheritance} ptr inheritance
    #{poke EXPLICIT_ACCESS_W, Trustee} ptr trustee

instance Storable TRUSTEE_W where
  alignment _ = #{alignment TRUSTEE_W}
  sizeOf _ = #{size TRUSTEE_W}
  peek ptr = do
    trusteeType <- #{peek TRUSTEE_W, TrusteeType} ptr
    trusteeForm <- #{peek TRUSTEE_W, TrusteeForm} ptr
    let _ = trusteeForm :: #{type TRUSTEE_FORM}
    --
    trusteeVal <- case trusteeForm of
      #{const TRUSTEE_IS_NAME} -> TRUSTEE_IS_NAME
        <$> #{peek TRUSTEE_W, ptstrName} ptr
      #{const TRUSTEE_IS_SID} -> TRUSTEE_IS_SID
        <$> #{peek TRUSTEE_W, ptstrName} ptr
      _ -> error "System.Win32.NamedPipe.Security: Unsupported trustee form"
    pure TRUSTEE_W {..}
  poke ptr TRUSTEE_W {..} = do
    #{poke TRUSTEE_W, pMultipleTrustee} ptr nullPtr
    #{poke TRUSTEE_W, MultipleTrusteeOperation} ptr
      (#{const NO_MULTIPLE_TRUSTEE} :: #{type MULTIPLE_TRUSTEE_OPERATION})
    #{poke TRUSTEE_W, TrusteeType} ptr trusteeType
    --
    let setForm :: #{type TRUSTEE_FORM} -> IO ()
        setForm = #{poke TRUSTEE_W, TrusteeForm} ptr
    case trusteeVal of
      TRUSTEE_IS_NAME name -> do
        setForm #{const TRUSTEE_IS_NAME}
        #{poke TRUSTEE_W, ptstrName} ptr name
      TRUSTEE_IS_SID sid -> do
        setForm #{const TRUSTEE_IS_SID}
        #{poke TRUSTEE_W, ptstrName} ptr sid
