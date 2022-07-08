# Byron Wallet Recovery

This repository is a collaborative attempt to find a solution affecting several users from the first days of Cardano who are today unable to spend funds that they own on old addresses. We make this effort public in hope that the peer-review & open source nature of it would prevent malicious actors to trick innocent users seeking help. In this repository, you'll find tools, scripts and instructions that are meant to help diagnose the issue. 

As of today, we haven't yet found a solution that works for everyone. Which is why we still need help investigating. 

<table> <tr> <td>
<h4>IMPORTANT DISCLAIMER</h4>
<hr/>
<strong>Do not share you secret credentials or private keys</strong> with anyone (even if they seem trustworthy). Tools and scripts from this repository will stick as much as possible to standard Cardano notations, which means that any message or string labelled with <code>xprv</code>, <code>prv</code>, <code>xsk</code> or <code>sk</code> refer to private material which <strong>must be kept secret</strong>.

<strong>Avoid also sharing screenshots</strong>, especially if you are not sure about whether the information on it may be sensitive.

<br/>

On the other hand messages or strings labelled as <code>xpub</code>, <code>pub</code>, <code>xvk</code>, <code>vk</code>, <code>addr</code> might be shared with trusted individuals. However, keep in mind that sharing public material will entail a loss of privacy, in particular the wallet root public key (labelled <code>root_xpub</code>) which will enable anyone knowing it to also identify <strong>all</strong> addresses belonging to your wallet.
</td> </tr> </table>

# How to Contribute? 

Please refer to [CONTRIBUTING.md](./CONTRIBUTING.md)

# Pre-requisites

If you want to follow steps described in this document, you'll need various tools of the Cardano ecosystem, as well as some ad-hoc tools from this repository. Yet, to get started, make sure to install / have available the following tools (please, refer to the respective repositories for installation instructions):

- [cardano-cli](https://github.com/input-output-hk/cardano-node/tree/master/cardano-cli#cardano-cli)
- [cardano-address](https://github.com/input-output-hk/cardano-addresses#command-line)
- [bech32](https://github.com/input-output-hk/bech32/#bech32-command-line)

# Current Situation

The investigation on the issue began back in December 2020 and has been tracked mostly in [cardano-wallet#2395](https://github.com/input-output-hk/cardano-wallet/issues/2395) which itself came from [daedalus#1234](https://github.com/input-output-hk/daedalus/issues/1234). Both tickets actually mention several, different, issues reported by ada holders. The ongoing effort isn't about helping those who lost their recovery phrase / mnemonic sentence. For those, there is not much that can be done. 

There is however a group of user who reportedly mention being in possession of their old keystore, are able to use the Daedalus recovery feature to load their keystore and see their funds in Daedalus but are unable to _spend them_. We'll attempt to summarize the findings and various areas explored in this document, while keeping the effort going on different fronts to figure out a solution. Keep in mind that, there may be flaw or missing pieces in those findings and we therefore strongly encourage anyone looking into this to **challenge and double-check reported findings**; do not take things for granted here.

When looking at source code, we've been mostly looking at `v1.0.1` and the dependency set defined in the corresponding [stack.yaml](https://github.com/input-output-hk/cardano-sl/blob/v1.0.1/stack.yaml) for that version. Why `v1.0.1`? Because, first of all, there's no `v1.0.0` which makes `v1.0.1` the first tagged version. It was tagged on September 27th (which is 2 days after the official launch of the Cardano mainnet). Since the issue seems to be affecting only very early ada holders (between the Launch and November 2017), it seems to be the _right moment_ to look at even though it is unclear whether this was indeed the version published at the time. 

## Table of Contents

- [KeyStore & 'secret.key' File](#keystore--secretkey-file)
- [Encrypted Secret Key](#encrypted-secret-key)
  - [BIP32-Ed25519](#bip32-ed25519)
  - [cardano-crypto & `XPrv`](#cardano-crypto--xprv)
  - [Passphrase Hash](#passphrase-hash)
  - [Child Key Derivation](#child-key-derivation)
- [Byron Addresses](#byron-addresses)
  - [Structural Overview](#overview)
  - [Encrypted Derivation Path Payload](#encrypted-derivation-path-payload)
- [Open Questions](#open-questions)

## KeyStore & 'secret.key' File

Before the introduction of recovery phrase (a.k.a mnemonic sentences), wallets in Cardano used to be attached to a keystore file, typically called `secret.key`. That file is a binary-encoded (CBOR) data structure which follows the following structure:

```cddl
keystore = [ vss, primKey, keys, walletSet ]

vss = [ 0*1 bytes .size 65 ]
primKey = [ 0*1 encryptedSecretKey ]
keys = [ * [ encryptedSecretKey, passphraseHash ] ]
walletSet = [ 0*1 wallet ]

wallet = 
  [ encryptedSecretKey
  , text
  , [ * (uint, text) ]
  , [ * (uint, uint) ]
  ]

encryptedSecretKey = bytes .size 128
passphraseHash = bytes .size 96
```

It is defined as the [`UserSecret`](https://github.com/input-output-hk/cardano-sl/blob/v1.0.1/node/src/Pos/Util/UserSecret.hs#L68-L75) data-type in the original codebase although the `_usPath` and `_usLock` from this data-type are not serialized in the keystore binary structure. Some interesting remarks: 

- In all keystores encountered so far, the `walletSet` has always been empty / unused. It supposedly contains the wallet's root key and derivation paths used by the wallet. 
- The provenance and use of the segregated primary key (a.k.a `primKey`) is still not fully known today. More on that later. 
- In most (all except the example ones) keystores encountered so far, the `keys` set has had up to one element.
- People that have been successfully restoring their old Byron wallets did so from the `keys` set.

## Encrypted Secret Key

### BIP32-Ed25519 

Cardano uses hierarchical deterministic key derivation mechanism inspired by [BIP-0032](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki) but applied to the Ed25519 elliptic curve. This scheme is commonly referred to as [BIP32-Ed25519](https://input-output-hk.github.io/adrestia/static/Ed25519_BIP.pdf). 

Some key take-aways from this key derivation scheme are the followings:

- The private key is extended through hashing algorithms to produce a key twice as long (i.e. 64 bytes) as standard Ed25519 signing keys.
- The key generation also implies the creation of a _chain-code_ which is used alongside the private & public keys.
- In addition to being used for signing messages, the extended private key can also be used for deriving child keys. 
- In the same spirit as BIP-0032, there exists two derivation methods: hardened and soft. 
- One can derive child public key from soft derivation, but can't from a hardened child. Hardened children can only have private descendent. 
- To be valid for signature, like for Ed25519 keys, an extended key must compel with some rules regarding the first half (a.k.a `kL`) of the extended key:

  - The third highest bit of the last byte must not be zero; 
  - The lowest 3 bits of the first byte should be cleared;
  - The highest bit of the last byte should be cleared;
  - The second highest bit of the last byte should be set;

  Or, in code:

  ```js
  if (kL[31] & 0b00100000) {
      return null;
  }

  kL[0]  &= 0b11111000;
  kL[31] &= 0b01111111;
  kL[31] |= 0b01000000;

  return kL;
  ```

### cardano-crypto & `XPrv`

Internally, encrypted secret keys (a.k.a `keys` field) in keystores where implemented on top of a data abstraction coming from [cardano-crypto](https://github.com/input-output-hk/cardano-crypto/). The library provides a data-type `XPrv` which is a wrapper around a byte array representing extended BIP32-Ed25519 key pairs. The wrapper provides in-memory encryption of the private part of the credentials. The `cardano-crypto` repository is a mix of Haskell code calling into C bits via FFI. The actual crypto is thus written in C, using somewhat ad-hoc functions and well-known primitives. 

When serialised, an `XPrv` can be represented as such:

```
+---------------------------------+-----------------------+-----------------------+
| Extended Private Key (64 bytes) | Public Key (32 bytes) | Chain Code (32 bytes) |
+---------------------------------+-----------------------+-----------------------+
<---------------------------------> 
        possibly encrypted
```

Note that the _Chain Code_ is used for [child key derivation](#child-key-derivation). The extended private material is said _possibly encrypted_ because, while the `XPrv` format supports in-memory encryption, the encryption can be (and has been) [skipped altogether by providing an empty byte-array as a passphrase](https://github.com/input-output-hk/cardano-crypto/blob/1cde8e3a8d9093bbf571085920045c05edb3eaa4/cbits/encrypted_sign.c#L59-L70). 

When encrypted, the key is encrypted using a ChaCha stream cipher with the following parameters:

- rounds = 20
- key size = 256 bits
- nonce size = 64 bits

Something to be careful about: the public key is 'cached' and always accessible! If one looks carefully at the implementation of cardano-crypto is that, the public key never re-computed from the private key. Incidentally, this means that there's no need to decrypt the private key in order to get the corresponding public key (which is great and useful in many cases). Yet, is also means that it isn't easily possible to verify whether the public key appended to a private key is indeed its public counter-part. Thus, a nice way to verify whether a key is encrypted is to try re-calculating the public key from a _possibly encrypted_ private part as described in the BIP-32-Ed25519 paper:  

```hs
import qualified Cardano.Crypto.Wallet.Encrypted as CC
import qualified Crypto.ECC.Edwards25519 as Ed25519
import           Crypto.Error
import qualified Data.ByteString as BS

publicKey :: CC.XPrv -> ByteString
publicKey (CC.unXPrv -> bytes) = fromJust $ do
  let (prv, _) = BS.splitAt 64 bytes
  ed25519ScalarMult (BS.take 32 prv)
  where
    ed25519ScalarMult :: ByteString -> Maybe ByteString
    ed25519ScalarMult bs = do
        scalar <- either (const Nothing) pure $ eitherCryptoError $ Ed25519.scalarDecodeLong bs
        pure $ Ed25519.pointEncode $ Ed25519.toPoint scalar
```

### Passphrase Hash 

The cardano-crypto library makes little assumption about the nature and source of the passphrase used for encryption. This has been mostly handled within the cardano-sl codebase. Which as far we can tell, only allowed passphrases to be either empty or exactly 32-byte long when set by the wallet client (see [Pos/Wallet/Web/ClientTypes/Instances](https://github.com/input-output-hk/cardano-sl/blob/v1.0.1/node/src/Pos/Wallet/Web/ClientTypes/Instances.hs#L207-L217) and [Pos.Crypto.Signing.Types.Safe](https://github.com/input-output-hk/cardano-sl/blob/v1.0.1/core/Pos/Crypto/Signing/Types/Safe.hs#L44-L45)). In practice, clients (i.e. Daedalus) would [submit a blake2b-256 hash digest of the user's passphrase](https://github.com/input-output-hk/cardano-sl/blob/v1.0.1/daedalus/src/Daedalus/Types.purs#L107-L110) effectively making them 32-byte long.

> Note that the previous paragraph describes the client interaction with the wallet API server at the time. However, it is also plausible that users may have set their passphrases through different means. It is therefore not guaranteed that passphrases are necessarily a blake2b-256 hash digest, nor that they are effectively always 32-byte long. However, it has been the case for wallets we've been able to successfully restore until now.

The passphrase itself was hashed as part of the flow of creating and manipulating an `EncryptedSecretKey` and stored next to the encrypted key in the keystore `keys`. This encryption was done using [`scrypt` with a randomly generated salt](https://github.com/input-output-hk/cardano-sl/blob/v1.0.1/core/Pos/Crypto/Scrypt.hs#L61-L65), and the following default parameters:

- logN = 14 
- r = 8 
- p = 1 
- digest length = 64

The salt, as well as the scrypt parameters were systematically packed with the hashed passphrase to form a standalone verifiable sequence of bytes. An important detail to remark is that passphrases where also [first serialized as CBOR](https://github.com/input-output-hk/cardano-sl/blob/v1.0.1/core/Pos/Crypto/Scrypt.hs#L58-L59) binary data before being hashed through the hashing algorithm. As a consequence, the hash of an _"empty passphrase"_ is in reality the hash of an empty CBOR bytestring (i.e. `40` in base16). 

It is therefore possible to check if a passphrases match a given hash present in the keystore using the following JavaScript snippet:

```js
const crypto = require('crypto');

function isMatchingPassphrase(source, target) {
  const [logN, r, p, salt, sourceHash] = source.toString('utf8').split('|');
  const opts = { N: 2 ** Number(logN), r: Number(r), p: Number(p) };
  const targetHash = crypto
    .scryptSync(target, Buffer.from(salt, 'base64'), 32, opts)
    .toString('base64');
  return sourceHash === targetHash;
}
```

### Child Key Derivation

The details of child key derivation are detailed in the [BIP32-Ed25519 paper](https://input-output-hk.github.io/adrestia/static/Ed25519_BIP.pdf). Index derivation allows to build a hierarchical structure ultimately coming from one single root key, and a set of derivation indexes. Indexes between `[0, 2^31-1]` are said _'soft'_ (or non-hardened) and indexes between `[2^31, 2^32-1]` are said _'hardened'_.

In the early days of Cardano, Byron addresses were [commonly derived on two levels](https://github.com/input-output-hk/cardano-sl/blob/v1.0.1/core/Pos/Core/Address.hs#L322-L334). The first index was called _'wallet index'_ and the second one _'account index'_. Later though, they were renamed respectively as _'account index'_ and _'address index'_. We will mostly use the latter naming but it also means that depending on which version of code we look at, _'account index'_ may refer to either the first or second level. As far as we know, the _'account index'_ was typically set to `2**31`.

These two indexes were meant to be hardened indexes only. However, a bug in the first version [fixed in November 2017](https://github.com/input-output-hk/cardano-sl/commit/4ebc883d4f08ffa13d3bce74e71792a3a54aeb42) caused the server to generate only soft indexes. It appears that the generator was used mainly for generating address indexes, which is why many early child key pair in Cardano were associated to a hardened account index and soft address index. Note that while bad, this also gives us an upper-bound of possible version(s) used by clients affected by the problem.  

> There was also another bug in the low-level implementation of the key derivation which [was fixed in February 2018](https://github.com/input-output-hk/cardano-crypto/commit/a635260ca5c2abcdf313bc7617da54543a357f7b). Later, a new wallet scheme was created (branded as 'Icarus') using the fixed version (a.k.a `DerivationScheme2`) while old Byron wallets kept on using the original version (a.k.a `DerivationScheme1`).

## Byron Addresses

### Overview
  
Byron addresses are now (almost fully) described in [CIP-0019](https://github.com/cardano-foundation/CIPs/blob/master/CIP-0019/CIP-0019-byron-addresses.cddl) and in particular, in [the associated CDDL specification](https://github.com/cardano-foundation/CIPs/blob/master/CIP-0019/CIP-0019-byron-addresses.cddl). A few interesting additions / things good-to-know: 

- On mainnet, the network discriminant was never included in the address attributes. 
- The public key associated with an address isn't directly embedded in the address. Only the _root_ is, which is a double-hash of some structure containing the key. 
  This makes it hard to know if a key is indeed owning a certain address, as one needs to reconstruct the entire root. A tiny error resulting in a complete different root. 

### Encrypted Derivation Path Payload

The derivation path in addresses were stored as byte strings, themselves being an encrypted authenticated ChaCha20/Poly1305 payload. The encryption passphrase was however fixed for every wallet and derived from the wallet's root public key (pbkdf2, see below).

```hs
import Crypto.Error
    ( CryptoError (..), CryptoFailable (..) )

import qualified Data.ByteString as BS
import qualified Crypto.Cipher.ChaChaPoly1305 as Poly
import qualified Crypto.KDF.PBKDF2 as PBKDF2
import qualified Data.ByteArray as BA
import qualified Cardano.Crypto.Wallet as CC

-- | ChaCha20/Poly1305 decrypting and authenticating the HD payload of addresses.
decryptDerivationPath
    :: CC.XPub
       -- ^ Symmetric key / passphrase, 32-byte long
    -> ByteString
        -- ^ Payload to be decrypted
    -> CryptoFailable ByteString
decryptDerivationPath xpub encryptedDerivationPath = do
    let (payload, tag) = BS.splitAt (BS.length encryptedDerivationPath - 16) encryptedDerivationPath
    nonce <- Poly.nonce12 hardCodedNonce
    st1 <- Poly.finalizeAAD <$> Poly.initialize (hdPassphrase xpub) nonce
    let (out, st2) = Poly.decrypt payload st1
    when (BA.convert (Poly.finalize st2) /= tag) $
        CryptoFailed CryptoError_MacKeyInvalid
    return out
  where
    -- | Hard-coded nonce from the legacy code-base.
    hardCodedNonce = "serokellfore"

hdPassphrase :: CC.XPub -> ScrubbedBytes
hdPassphrase xpub =
    PBKDF2.generate
      (PBKDF2.prfHMAC SHA512)
      (PBKDF2.Parameters 500 32)
      (CC.xpubPublicKey xpub <> CC.xpubChainCode xpub)
      ("address-hashing" :: ByteString)
```

> **TODO**: re-write in JavaScript / Python, and move as script to `tools` 

## Open Questions

> **TODO**: questions below are listed as memo, but more details is needed about what they actually mean and what was already investigated.

##### Discrepancy between keystore's reported passphrase hash and actual passphrase?

##### Difference between regular | paperVended | forceVended redemption modes?

##### What happened to cardano-sl v1.0.0?
