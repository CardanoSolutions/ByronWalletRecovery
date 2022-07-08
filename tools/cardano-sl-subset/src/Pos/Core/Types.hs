{-# LANGUAGE UndecidableInstances #-}
module Pos.Core.Types where

import Universum

import Cardano.Crypto.Wallet
    ( deriveXPrv, deriveXPub, unXPub )
import qualified Cardano.Crypto.Wallet as CC
import qualified Crypto.Cipher.ChaChaPoly1305 as C
import Crypto.Error
import Crypto.Hash
    ( Blake2b_224, Blake2b_256, Digest, HashAlgorithm, SHA512 (..) )
import qualified Crypto.Hash as Hash
import qualified Crypto.KDF.PBKDF2 as PBKDF2
import qualified Crypto.MAC.Poly1305 as Poly
import Data.ByteArray as BA
    ( convert )
import qualified Data.ByteArray as ByteArray
import qualified Data.ByteString.Base16 as B16
import Data.ByteString.Char8 as B
import Data.Data
    ( Data )
import Data.Hashable
    ( Hashable )
import qualified Data.Hashable as Hashable
import qualified Data.Text as T
import qualified Data.Text.Encoding as T
import Pos.Binary.Class
    ( Bi, Raw, decodeFull, serialize' )
import qualified Pos.Binary.Class as Bi
import Pos.Crypto.Hashing
    ( AbstractHash, hash )
import Pos.Data.Attributes
    ( Attributes )
import qualified Prelude


----------------------------------------------------------------------------
-- Address, StakeholderId
----------------------------------------------------------------------------

-- | Hash used to identify address.
type AddressHash = AbstractHash Blake2b_224

-- | Data which is bound to an address and must be revealed in order
-- to spend coins belonging to this address.
data AddrSpendingData
    = PubKeyASD !PublicKey
--    -- ^ Funds can be spent by revealing a 'PublicKey' and providing a
--    -- valid signature.
--    | ScriptASD !Script
--    -- ^ Funds can be spent by revealing a 'Script' and providing a
--    -- redeemer 'Script'.
--    | RedeemASD !RedeemPublicKey
--    -- ^ Funds can be spent by revealing a 'RedeemScript' and providing a
--    -- valid signature.
    | UnknownASD !Word8 !ByteString
    -- ^ Unknown type of spending data. It consists of a tag and
    -- arbitrary 'ByteString'. It allows us to introduce a new type of
    -- spending data via softfork.
    deriving (Eq, Generic, Typeable, Show)

-- | Type of an address. It corresponds to constructors of
-- 'AddrSpendingData'. It's separated, because 'Address' doesn't store
-- 'AddrSpendingData', but we want to know its type.
data AddrType
    = ATPubKey
    | ATScript
    | ATRedeem
    | ATUnknown !Word8
    deriving (Eq, Ord, Generic, Typeable, Show)

-- | Stake distribution associated with an address.
data AddrStakeDistribution
    = BootstrapEraDistr
--    -- ^ Stake distribution for bootstrap era.
--    | SingleKeyDistr !StakeholderId
--    -- ^ Stake distribution stating that all stake should go to the given stakeholder.
--    | UnsafeMultiKeyDistr !(Map StakeholderId CoinPortion)
--    -- ^ Stake distribution which gives stake to multiple
--    -- stakeholders. 'CoinPortion' is a portion of an output (output
--    -- has a value, portion of this value is stake). The constructor
--    -- is unsafe because there are some predicates which must hold:
--    --
--    -- • the sum of portions must be @maxBound@ (basically 1);
--    -- • all portions must be positive;
--    -- • there must be at least 2 items, because if there is only one item,
--    -- 'SingleKeyDistr' can be used instead (which is smaller).
    deriving (Eq, Ord, Show, Generic, Typeable)

-- | Additional information stored along with address. It's intended
-- to be put into 'Attributes' data type to make it extensible with
-- softfork.
data AddrAttributes = AddrAttributes
    { aaPkDerivationPath  :: !(Maybe HDAddressPayload)
    , aaStakeDistribution :: !AddrStakeDistribution
    } deriving (Eq, Ord, Show, Generic, Typeable)

-- | Hash of this data is stored in 'Address'. This type exists mostly
-- for internal usage.
newtype Address' = Address'
    { unAddress' :: (AddrType, AddrSpendingData, Attributes AddrAttributes)
    } deriving (Eq, Show, Generic, Typeable)

-- | 'Address' is where you can send coins.
data Address = Address
    { addrRoot       :: !(AddressHash Address')
    -- ^ Root of imaginary pseudo Merkle tree stored in this address.
    , addrAttributes :: !(Attributes AddrAttributes)
    -- ^ Attributes associated with this address.
    , addrType       :: !AddrType
    -- ^ The type of this address. Should correspond to
    -- 'AddrSpendingData', but it can't be checked statically, because
    -- spending data is hashed.
    } deriving (Eq, Ord, Generic, Typeable, Show)

instance NFData AddrType
instance NFData AddrSpendingData
instance NFData AddrAttributes
instance NFData AddrStakeDistribution
instance NFData Address

----------------------------------------------------------------------------
-- Signing
----------------------------------------------------------------------------

-- | Wrapper around 'CC.XPub'.
newtype PublicKey = PublicKey CC.XPub
    deriving (Eq, Ord, Show, Generic, NFData, Hashable, Typeable)

-- | Wrapper around 'CC.XPrv'.
newtype SecretKey = SecretKey CC.XPrv
    deriving (NFData)

-- | Generate a public key from a secret key. Fast (it just drops some bytes
-- off the secret key).
toPublic :: SecretKey -> PublicKey
toPublic (SecretKey k) = PublicKey (CC.toXPub k)

-- | Direct comparison of secret keys is a security issue (cc @vincent)
instance Bi SecretKey => Eq SecretKey where
    a == b = hash a == hash b

instance Show SecretKey where
    show sk = "<secret of " ++ show (toPublic sk) ++ ">"

instance Bi CC.ChainCode where
    encode (CC.ChainCode c) = Bi.encode c
    decode = CC.ChainCode <$> Bi.decode

instance Bi CC.XPub where
    encode (CC.unXPub -> kc) = Bi.encode kc
    decode = either fail pure . CC.xpub =<< Bi.decode

instance Bi CC.XPrv where
    encode (CC.unXPrv -> kc) = Bi.encode kc
    decode = either fail pure . CC.xprv =<< Bi.decode @ByteString

deriving instance Bi PublicKey
deriving instance Bi SecretKey

data EncryptedSecretKey = EncryptedSecretKey
    { eskPayload :: !CC.XPrv          -- ^ Secret key itself
    }

instance Show EncryptedSecretKey where
    show _ = "<encrypted key>"

encToPublic :: EncryptedSecretKey -> PublicKey
encToPublic (EncryptedSecretKey sk) = PublicKey (CC.toXPub sk)

----------------------------------------------------------------------------
-- HD
----------------------------------------------------------------------------

-- | HDAddressPayload consists of
--
-- * serialiazed and encrypted with symmetric scheme path from the
-- root key to given descendant key with passphrase (using
-- ChaChaPoly1305 algorithm)
--
-- * cryptographic tag
--
-- For more information see 'packHDAddressAttr' and 'encryptChaChaPoly'.
data HDAddressPayload
    = HDAddressPayload
    { getHDAddressPayload :: !ByteString
    } deriving (Eq, Ord, Show, Generic)

instance NFData HDAddressPayload

instance Bi HDAddressPayload where
    encode (HDAddressPayload payload) = Bi.encode payload
    decode = HDAddressPayload <$> Bi.decode

-- | Passphrase is a hash of root public key.
--- We don't use root public key to store money, we use its hash instead.
data HDPassphrase = HDPassphrase !ByteString
    deriving Show
