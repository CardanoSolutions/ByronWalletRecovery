module Main where

import Prelude


import qualified Cardano.Crypto.Wallet as CC
import qualified Cardano.Crypto.Wallet.Encrypted as CC
import qualified Codec.CBOR.Decoding as CBOR
import qualified Codec.CBOR.Read as CBOR
import Control.Concurrent
    ( myThreadId )
import Control.Concurrent.Async
    ( mapConcurrently_ )
import Control.Monad
import qualified Crypto.ECC.Edwards25519 as Ed25519
import Crypto.Error
import Crypto.Hash
    ( Blake2b_256, hash )
import Data.ByteArray
    ( ByteArrayAccess )
import qualified Data.ByteArray as BA
import Data.ByteString
    ( ByteString )
import qualified Data.ByteString as BS
import Data.ByteString.Base16
import qualified Data.ByteString.Base16 as B16
import qualified Data.ByteString.Char8 as B8
import qualified Data.ByteString.Lazy as BL
import Data.Maybe
import Data.Text
    ( Text )
import qualified Data.Text as T
import qualified Data.Text.Encoding as T
import Data.Word
    ( Word8 )
import qualified Pos.Binary.Class as Bi
import Pos.Binary.Core.Address
    ()
import Pos.Core.Address
    ( addrToBase58, deriveLvl2KeyPair, makePubKeyHdwAddress )
import Pos.Core.Types
    ( Address (..), EncryptedSecretKey (EncryptedSecretKey), PublicKey (..) )
import Pos.Data.Attributes
    ( mkAttributes )
import System.Environment

-- | Construct an address from a root private key and a derivation path (2 levels).
--
-- Usage:
--
--     stack run cardano-sl-subset:exe:create-address -- [Base16 Xprv] [Account Index] [Address Index]
--
main :: IO ()
main = do
  [_, xprv, acctIx, addrIx] <- getArgs
  let Just (addr, _) = deriveLvl2KeyPair
        (EncryptedSecretKey (unsafeXPrv (unsafeBase16Decode (T.pack xprv))))
        (read acctIx)
        (read addrIx)
  B8.putStrLn (addrToBase58 addr)

unsafeXPub :: ByteString -> CC.XPub
unsafeXPub = either error id . CC.xpub

unsafeXPrv :: ByteString -> CC.XPrv
unsafeXPrv = either error id . CC.xprv

unsafeBase16Decode :: Text -> ByteString
unsafeBase16Decode =
  either error id . B16.decode . T.encodeUtf8

blake2b256 :: ByteString -> ByteString
blake2b256 =
  BA.convert . hash @_ @Blake2b_256
