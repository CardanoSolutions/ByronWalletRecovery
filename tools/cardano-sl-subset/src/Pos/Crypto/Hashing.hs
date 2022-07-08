{-# LANGUAGE AllowAmbiguousTypes #-}
{-# LANGUAGE RankNTypes #-}

-- | Hashing capabilities.

module Pos.Crypto.Hashing
       (
         -- * WithHash
         WithHash (..)
       , withHash

         -- * AbstractHash
       , AbstractHash (..)
       , decodeAbstractHash
       , decodeHash
       , abstractHash
       , unsafeAbstractHash

         -- * Common Hash
       , Hash
       , hash
       , hashRaw
       , unsafeHash

         -- * Utility
       , CastHash (castHash)
       , HashAlgorithm
       , hashDigestSize'
       ) where

import Universum

import Control.Arrow
    ( left )
import Crypto.Hash
    ( Blake2b_256, Digest, HashAlgorithm, hashDigestSize )
import qualified Crypto.Hash as Hash
import qualified Data.ByteArray as ByteArray
import qualified Data.ByteString.Base16 as B16
import Data.Hashable
    ( Hashable (hashWithSalt), hashPtrWithSalt )
import qualified Data.Text as T
import qualified Data.Text.Encoding as T
import Pos.Binary.Class
    ( Bi, Raw )
import qualified Pos.Binary.Class as Bi
import qualified Prelude
import System.IO.Unsafe
    ( unsafeDupablePerformIO )

----------------------------------------------------------------------------
-- WithHash
----------------------------------------------------------------------------

data WithHash a = WithHash
    { whData :: a
    , whHash :: Hash a
    } deriving (Show, Typeable)

instance Hashable (WithHash a) where
    hashWithSalt s = hashWithSalt s . whHash

instance Eq a => Eq (WithHash a) where
    a == b = (whHash a == whHash b) && (whData a == whData b)

instance Ord a => Ord (WithHash a) where
    a <= b = whData a <= whData b

withHash :: Bi a => a -> WithHash a
withHash a = WithHash a (force h)
  where
    h = hash a

-- | Hash wrapper with phantom type for more type-safety.
-- Made abstract in order to support different algorithms in
-- different situations
newtype AbstractHash algo a = AbstractHash (Digest algo)
    deriving (Show, Eq, Ord, ByteArray.ByteArrayAccess, Generic, NFData)

instance HashAlgorithm algo => Read (AbstractHash algo a) where
    readsPrec _ s = case B16.decode (T.encodeUtf8 (T.pack s)) of
        Left _   -> []
        Right bs -> case Hash.digestFromByteString bs of
            Nothing -> []
            Just h  -> [(AbstractHash h, "")]

instance Hashable (AbstractHash algo a) where
    hashWithSalt s h =
        unsafeDupablePerformIO $
        ByteArray.withByteArray h (\ptr -> hashPtrWithSalt ptr len s)
      where
        !len = ByteArray.length h

hashDigestSize' :: forall algo . HashAlgorithm algo => Int
hashDigestSize' = hashDigestSize @algo
    (error "Pos.Crypto.Hashing.hashDigestSize': HashAlgorithm value is evaluated!")

-- | Parses given hash in base16 form.
decodeAbstractHash ::
       forall algo a. HashAlgorithm algo
    => Text
    -> Either Text (AbstractHash algo a)
decodeAbstractHash prettyHash = do
    bytes <- left T.pack $ B16.decode (T.encodeUtf8 prettyHash)
    case Hash.digestFromByteString bytes of
        Nothing ->
            Left
                ("decodeAbstractHash: " <> "can't convert bytes to hash," <>
                 " the value was " <> prettyHash)
        Just digest -> return (AbstractHash digest)

-- | Parses given hash in base16 form.
decodeHash :: Bi (Hash a) => Text -> Either Text (Hash a)
decodeHash = decodeAbstractHash @Blake2b_256

-- | Encode thing as 'Binary' data and then wrap into constructor.
abstractHash
    :: (HashAlgorithm algo, Bi a)
    => a -> AbstractHash algo a
abstractHash = unsafeAbstractHash

-- | Unsafe version of abstractHash.
unsafeAbstractHash
    :: (HashAlgorithm algo, Bi a)
    => a -> AbstractHash algo b
unsafeAbstractHash = AbstractHash . Hash.hash . Bi.serialize'

-- | Type alias for commonly used hash
type Hash = AbstractHash Blake2b_256

-- | Short version of 'unsafeHash'.
hash :: Bi a => a -> Hash a
hash = unsafeHash

-- | Raw constructor application.
hashRaw :: ByteString -> Hash Raw
hashRaw = AbstractHash . Hash.hash

-- | Encode thing as 'Bi' data and then wrap into constructor.
unsafeHash :: Bi a => a -> Hash b
unsafeHash = unsafeAbstractHash

-- | Type class for unsafe cast between hashes.
-- You must ensure that types have identical Bi instances.
class CastHash a b where
    castHash :: AbstractHash algo a -> AbstractHash algo b
    castHash (AbstractHash x) = AbstractHash x

instance CastHash a a where
    castHash = id

-- | Instances for `Raw` hashes for ease of casting
instance CastHash Raw a
instance CastHash a Raw
