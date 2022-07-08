module Pos.Binary.Crypto where

import Universum

import Crypto.Hash
    ( digestFromByteString )
import qualified Data.ByteArray as ByteArray
import Pos.Binary.Class
    ( Bi (..) )
import Pos.Crypto.Hashing
    ( AbstractHash (..), HashAlgorithm, WithHash (..), withHash )

----------------------------------------------------------------------------
-- Hashing
----------------------------------------------------------------------------

instance (Typeable algo, Typeable a, HashAlgorithm algo) => Bi (AbstractHash algo a) where
    encode (AbstractHash digest) = encode (ByteArray.convert digest :: ByteString)
    decode = do
        bs <- decode @ByteString
        case digestFromByteString bs of
            Nothing -> fail "AbstractHash.decode: invalid digest"
            Just x  -> pure (AbstractHash x)
