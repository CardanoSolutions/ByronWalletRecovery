#!/usr/bin/env node

// Usage:
//
//     ./index.js [FILEPATH]
//
// Example:
//
//     ./index.js examples/secret.key

const cbor = require('cbor');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { bech32 } = require('bech32');

const [_1, _2, keystorePath] = process.argv;

const bytes = fs.readFileSync(path.isAbsolute(keystorePath)
  ? keystorePath
  : path.join(__dirname, keystorePath));

decodeKeystore(bytes)
  .then(displayInformation)
  .then(console.log)
  .catch(console.exception);

function toEncryptedSecretKey ([encryptedPayload, passphraseHash], source) {
  const isEmptyPassphrase = $isEmptyPassphrase(passphraseHash);

  // The payload is a concatenation of the private key, the public key
  // and the chain-code:
  //
  //      +---------------------------------+-----------------------+-----------------------+
  //      | Extended Private Key (64 bytes) | Public Key (32 bytes) | Chain Code (32 bytes) |
  //      +---------------------------------+-----------------------+-----------------------+
  //      <------------ ENCRYPTED ---------->
  //
  const xprv = encryptedPayload.slice(0, 64);
  const xpub = encryptedPayload.slice(64, 96);
  const cc = encryptedPayload.slice(96);

  return {
    xprv,
    xpub,
    cc,
    encryptedPayload,
    passphraseHash,
    isEmptyPassphrase,
    source,
  };
}

// Keystores were always encrypted with a passphrase, at least on the server. For a while,
// the frontend (a.k.a Daedalus) did allow users to generate wallets with no encryption
// passphrase, in which case it used to send an empty string as a passphrase to the server.
//
// Thus, is possible to know if a passphrase is an "empty passphrase" by comparing it with
// a CBOR-serialized empty bytestring (`0x40`). The salt used for encryption is embedded in
// passphrase.
function $isEmptyPassphrase (pwd) {
  const cborEmptyBytes = Buffer.from('40', 'hex');
  const [logN, r, p, salt, hashA] = pwd.toString('utf8').split('|');
  const opts = { N: 2 ** Number(logN), r: Number(r), p: Number(p) };
  const hashB = crypto
    .scryptSync(cborEmptyBytes, Buffer.from(salt, 'base64'), 32, opts)
    .toString('base64');
  return hashA === hashB;
}

// The keystore is "just" a CBOR-encoded 'UserSecret' as detailed below.
async function decodeKeystore (bytes) {
  return cbor.decodeAll(bytes).then((obj) => {
    /**
     * The original 'UserSecret' from cardano-sl looks like this:
     *
     * ```hs
     * data UserSecret = UserSecret
     *     { _usVss       :: Maybe VssKeyPair
     *     , _usPrimKey   :: Maybe SecretKey
     *     , _usKeys      :: [EncryptedSecretKey]
     *     , _usWalletSet :: Maybe WalletUserSecret
     *     , _usPath      :: FilePath
     *     , _usLock      :: Maybe FileLock
     *     }
     *
     * data WalletUserSecret = WalletUserSecret
     *     { _wusRootKey    :: EncryptedSecretKey
     *     , _wusWalletName :: Text
     *     , _wusAccounts   :: [(Word32, Text)]
     *     , _wusAddrs      :: [(Word32, Word32)]
     *     }
     * ```
     *
     * We are interested in:
     * - usKeys:
     *    which is where keys have been stored since ~2018
     *
     * - usWalletSet
     *    which seems to have been used in earlier version; at least the
     *    wallet from the time did allow to restore so-called 'wallets'
     *    from keys coming from that 'WalletUserSecret'
     */
    const usKeys = obj[0][2].map((x) => toEncryptedSecretKey(x, "_usKeys"));
    const usWalletSet = obj[0][3].map((x) => toEncryptedSecretKey(x[0], "_usWalletSet"));
    return usKeys.concat(usWalletSet);
  });
}

function displayInformation(keystore) {
  const display = ({ xprv, xpub, cc, isEmptyPassphrase, source }) => {
    return {
      "encrypted-root-private-key": encodeBech32("root_xsk", Buffer.concat([xprv, cc])),
      "root-public-key": encodeBech32("root_xvk", Buffer.concat([xpub, cc])),
      source,
      "is-empty-passphrase": isEmptyPassphrase,
    }
  };
  return JSON.stringify(keystore.map(display), null, 4);
}

function encodeBech32(prefix, bytes) {
  const words = bech32.toWords(bytes);
  const MAX_LENGTH = 999; // long-enough, Cardano uses bech32 for long strings.
  return bech32.encode(prefix, words, MAX_LENGTH);
}
