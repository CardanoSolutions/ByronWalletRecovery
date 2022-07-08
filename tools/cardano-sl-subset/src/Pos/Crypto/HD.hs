module Pos.Crypto.HD where

import Universum

import Cardano.Crypto.Wallet
    ( DerivationScheme (DerivationScheme1), deriveXPrv, deriveXPub, unXPub )
import qualified Crypto.Cipher.ChaChaPoly1305 as C
import Crypto.Error
import Crypto.Hash
    ( SHA512 (..) )
import qualified Crypto.KDF.PBKDF2 as PBKDF2
import qualified Crypto.MAC.Poly1305 as Poly
import Data.ByteArray as BA
    ( convert )
import Data.ByteString.Char8 as B
import Pos.Binary.Class
    ( Bi, decodeFull, serialize' )
import Pos.Core.Types
    ( EncryptedSecretKey (EncryptedSecretKey)
    , HDAddressPayload (..)
    , HDPassphrase (..)
    , PublicKey (..)
    )

firstHardened :: Word32
firstHardened = 2 ^ (31 :: Word32)

-- | Derive secret key from secret key.
deriveHDSecretKey
    :: EncryptedSecretKey -> Word32 -> Maybe EncryptedSecretKey
deriveHDSecretKey (EncryptedSecretKey xprv) childIndex =
    pure $ EncryptedSecretKey (deriveXPrv DerivationScheme1 (mempty :: ByteString) xprv childIndex)

-- | Compute passphrase as hash of the root public key.
deriveHDPassphrase :: PublicKey -> HDPassphrase
deriveHDPassphrase (PublicKey pk) = HDPassphrase $
    PBKDF2.generate
        (PBKDF2.prfHMAC SHA512)
        (PBKDF2.Parameters
             500 -- Parameters for the hashing function. 500 iter of PBDKF2 with HMAC-SHA256
             passLen)
        (unXPub pk)
        ("address-hashing"::ByteString)
  where
    -- Password length in bytes
    passLen = 32

addrAttrNonce :: ByteString
addrAttrNonce = "serokellfore"

-- | Serialize tree path and encrypt it using passphrase via ChaChaPoly1305.
packHDAddressAttr :: HDPassphrase -> [Word32] -> HDAddressPayload
packHDAddressAttr (HDPassphrase passphrase) path = do
    let !pathSer = serialize' path
    let !packCF =
          encryptChaChaPoly
              addrAttrNonce
              passphrase
              ""
              pathSer
    case packCF of
        CryptoFailed er -> error $ "Error in packHDAddressAttr: " <> show er
        CryptoPassed p  -> HDAddressPayload p

-- Wrapper around ChaChaPoly1305 module.
encryptChaChaPoly
    :: ByteString -- Nonce (12 random bytes)
    -> ByteString -- Symmetric key (must be 32 bytes)
    -> ByteString -- Encryption header.
                  -- Header is chunk of data we want to transfer unecncrypted
                  -- but still want it to be part of tag digest.
                  -- So tag verifies validity of both encrypted data and unencrypted header.
    -> ByteString -- Input plaintext to be encrypted
    -> CryptoFailable ByteString -- Ciphertext with a 128-bit tag attached
encryptChaChaPoly nonce key header plaintext = do
    st1 <- C.nonce12 nonce >>= C.initialize key
    let st2 = C.finalizeAAD $ C.appendAAD header st1
    let (out, st3) = C.encrypt plaintext st2
    let auth = C.finalize st3
    pure $ out <> BA.convert auth
