{-# LANGUAGE RecordWildCards #-}

module Pos.Core.Address where

import Universum

import Crypto.Hash
    ( Blake2b_224, Digest, SHA3_256 )
import qualified Crypto.Hash as CryptoHash
import Data.ByteString.Base58
    ( bitcoinAlphabet, encodeBase58 )
import Pos.Binary.Class
    ( Bi )
import qualified Pos.Binary.Class as Bi
import Pos.Core.Types
    ( AddrAttributes (..)
    , AddrSpendingData (..)
    , AddrStakeDistribution (..)
    , AddrType (..)
    , Address (..)
    , Address' (..)
    , AddressHash
    , EncryptedSecretKey
    , HDAddressPayload
    , HDPassphrase
    , PublicKey
    , encToPublic
    )
import Pos.Crypto.Hashing
    ( AbstractHash (AbstractHash) )
import Pos.Crypto.HD
    ( deriveHDPassphrase, deriveHDSecretKey, packHDAddressAttr )
import Pos.Data.Attributes
    ( mkAttributes )

addrToBase58 :: Bi Address => Address -> ByteString
addrToBase58 = encodeBase58 bitcoinAlphabet . Bi.serialize'

-- | Make an 'Address' from spending data and attributes.
makeAddress :: Bi Address' => AddrSpendingData -> AddrAttributes -> Address
makeAddress spendingData attributesUnwrapped =
    Address
    { addrRoot = addressHash address'
    , addrAttributes = attributes
    , ..
    }
  where
    addrType = addrSpendingDataToType spendingData
    attributes = mkAttributes attributesUnwrapped
    address' = Address' (addrType, spendingData, attributes)

-- | Convert 'AddrSpendingData' to the corresponding 'AddrType'.
addrSpendingDataToType :: AddrSpendingData -> AddrType
addrSpendingDataToType =
    \case
        PubKeyASD {} -> ATPubKey
        -- ScriptASD {} -> ATScript
        -- RedeemASD {} -> ATRedeem
        UnknownASD tag _ -> ATUnknown tag

unsafeAddressHash :: Bi a => a -> AddressHash b
unsafeAddressHash = AbstractHash . secondHash . firstHash
  where
    firstHash :: Bi a => a -> Digest SHA3_256
    firstHash = CryptoHash.hash . Bi.serialize'
    secondHash :: Digest SHA3_256 -> Digest Blake2b_224
    secondHash = CryptoHash.hash

addressHash :: Bi a => a -> AddressHash a
addressHash = unsafeAddressHash

-- | Makes account secret key for given wallet set.
deriveLvl2KeyPair
    :: Bi Address'
    => EncryptedSecretKey -- ^ key of wallet set
    -> Word32 -- ^ wallet derivation index
    -> Word32 -- ^ account derivation index
    -> Maybe (Address, EncryptedSecretKey)
deriveLvl2KeyPair wsKey walletIndex accIndex = do
    wKey <- deriveHDSecretKey wsKey walletIndex
    let hdPass = deriveHDPassphrase $ encToPublic wsKey
    createHDAddressH hdPass wKey [walletIndex] accIndex
  where
  -- | Create address from secret key in hardened way.
  createHDAddressH
      :: Bi Address'
      => HDPassphrase
      -> EncryptedSecretKey
      -> [Word32]
      -> Word32
      -> Maybe (Address, EncryptedSecretKey)
  createHDAddressH walletPassphrase parent parentPath childIndex = do
      derivedSK <- deriveHDSecretKey parent childIndex
      let addressPayload = packHDAddressAttr walletPassphrase $ parentPath ++ [childIndex]
      let pk = encToPublic derivedSK
      return (makePubKeyHdwAddress (Just addressPayload) pk, derivedSK)

makePubKeyHdwAddress
    :: Bi Address'
    => Maybe HDAddressPayload
    -> PublicKey
    -> Address
makePubKeyHdwAddress path key =
    makeAddress spendingData attrs
  where
    spendingData = PubKeyASD key
    distr = BootstrapEraDistr
    attrs = AddrAttributes {aaStakeDistribution = distr, aaPkDerivationPath = path}
