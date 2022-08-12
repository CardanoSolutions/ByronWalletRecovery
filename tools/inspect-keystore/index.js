#!/usr/bin/env node

// Install:
//
// npm i cbor bech32 cardano-crypto.js@6.1.1
//
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
const cardano = require('cardano-crypto.js')

const [_1, _2, keystorePath, candidatePassword, byronAddress] = process.argv;

const bytes = fs.readFileSync(path.isAbsolute(keystorePath) ?
  keystorePath :
  path.join(__dirname, keystorePath));

decodeKeystore(bytes)
  .then((keystore) => validateKeystore(keystore, candidatePassword, byronAddress))
  .then(console.log)
  .catch(console.exception);

function toEncryptedSecretKey([encryptedPayload, passphraseHash], source) {
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
function $isEmptyPassphrase(pwd) {
  const cborEmptyBytes = Buffer.from('40', 'hex');
  const [logN, r, p, salt, hashA] = pwd.toString('utf8').split('|');
  const opts = {
    N: 2 ** Number(logN),
    r: Number(r),
    p: Number(p)
  };
  const hashB = crypto
    .scryptSync(cborEmptyBytes, Buffer.from(salt, 'base64'), 32, opts)
    .toString('base64');
  return hashA === hashB;
}

// The keystore is "just" a CBOR-encoded 'UserSecret' as detailed below.
async function decodeKeystore(bytes) {
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
  const display = ({
    xprv,
    xpub,
    cc,
    isEmptyPassphrase,
    source,
    hasValidKey,
    address,
    path
  }) => {
    return {
      "encrypted-root-private-key": encodeBech32("root_xsk", Buffer.concat([xprv, cc])),
      "root-public-key": encodeBech32("root_xvk", Buffer.concat([xpub, cc])),
      source,
      "is-empty-passphrase": isEmptyPassphrase,
      "has-valid-key": hasValidKey,
      "address": address,
      "path": path
    }
  };
  return JSON.stringify(keystore.map(display), null, 4);
}

function encodeBech32(prefix, bytes) {
  const words = bech32.toWords(bytes);
  const MAX_LENGTH = 999; // long-enough, Cardano uses bech32 for long strings.
  return bech32.encode(prefix, words, MAX_LENGTH);
}


/*
 * Steps for wallet validation:
 *   0. Check whether the user's provided address, if there is any,  belongs to this Wallet.
 *   1. Is the current wallet based on `_usKeys` or `_usWalletSet`?
 *     a. If _usWallets go to point 3.
 *   2. Is the wallet has and empty-hash?
 *     a. if no, try to decrypt the encrypted secret key with the user's provided password.
 *   3. Can the secret key regenerate its stored public key?
 *     a. if no, then try to decrypt the encrypted secret key with the user's provided password,
 *     b. as it means that the private key in the master secret is encrypted or corrupted or
 *     c. the public key is corrupted, etc.
 *   4. Create a wallet recovery key secret.key based on the secret key. 
 */
async function validateKeystore(keystore, userPwd, byronaddress) {
  const validated = async (key) => {

    // TODO: 0. If the byron address is defined, check whether it belongs to 
    // the wallet or not.
    try {
      /// 1st check. Check whether
      const hdp = await cardano.xpubToHdPassphrase(Buffer.concat([key.xpub, key.cc]))
      const addrBuf = await cardano.addressToBuffer(byronaddress)
      const path = cardano.getBootstrapAddressDerivationPath(addrBuf, hdp)
      key.address = byronaddress
      key.path = path
      // console.log(`${byronaddress} versus. ${dp}`)
    } catch (e) {
      //  console.log(`Address ${byronAddress} does not belong to root public key examined. ${e}`)
      key.address = ""
      key.path = []
    }

    // TODO: 1. is it _usWallet or _usWalletSet based wallet?


    // TODO: 2. Does the wallet has empty password based `passwordHash`

    // NOTE: 3. Check whether that the stored master public key is the same
    // with the generated from the store master private key. This ensures that
    // the master secret is not encrypted.
    const isDecrypted = checkEncryption(key.xprv, key.xpub)
    key.hasValidKey = key.isEmptyPassphrase ?
      (isDecrypted ? "true" : "false") :
      "unsure, more verification required"

    // TODO: 3.a. Try to decrypt the encrypted sk with the user's provided password.
    if (!isDecrypted) {
      // FIXME: Vacumlabs cardano memory combine seems to be add and additional blake2b_512 stratching.
      // 
      const prv = await cardano.cardanoMemoryCombine(key.xprv, userPwd)
      if (checkEncryption(prv, key.xpub)) {
        console.log(`The decryption was successfull`)
      } else {
        console.log(`The decryption was un-successfull`)
      }
    }
    return key;
  }

  const asyncRes = await Promise.all(keystore.map(validated));

  return displayInformation(asyncRes)
}

function checkEncryption(prv, pub) {
  const genPub = cardano.toPublic(prv)
  return Buffer.compare(pub, genPub) == 0
}
