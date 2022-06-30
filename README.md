# Byron Wallet Recovery

This repository is a collaborative attempt to find a solution affecting several users from the first days of Cardano who are today unable to spend funds that they own on old addresses. We make this effort public in hope that the peer-review & open source nature of it would prevent malicious actors to trick innocent users seeking help. In this repository, you'll find tools, scripts and instructions that are meant to help diagnose the issue. 

As of today, we haven't yet found a solution that works for everyone. Which is why we still need help investigating. 

<table> <tr> <td>
<h4>IMPORTANT DISCLAIMER</h4>
<hr/>
<strong>Do not share you secret credentials or private keys</strong> with anyone (even if they seem trustworthy). Tools and scripts from this repository will stick as much as possible to standard Cardano notations, which means that any message or string labelled with <code>xprv</code>, <code>prv</code>, <code>xsk</code> or <code>sk</code> refer to private material which <strong>must be kept secret</strong>.

Avoid also sharing screenshot, especially if you are not sure about whether the information on it may be sensitive.

<br/>

On the other hand messages or strings labelled as <code>xpub</code>, <code>pub</code>, <code>xvk</code>, <code>vk</code>, <code>addr</code> might be share with trusted individuals. However, keep in mind that sharing public material will entail a loss of privacy, in particular the wallet root public key (labelled <code>root_xpub</code>) which will enable anyone knowing it to also identify <strong>all</strong> addresses belonging to your wallet.
</td> </tr> </table>

# Pre-requisites

If you want to follow steps described in this document, you'll need various tools of the Cardano ecosystem, as well as some ad-hoc tools from this repository. Yet, to get started, make sure to install / have available the following tools (please, refer to the respective repositories for installation instructions):

- [cardano-cli](https://github.com/input-output-hk/cardano-node/tree/master/cardano-cli#cardano-cli)
- [cardano-address](https://github.com/input-output-hk/cardano-addresses#command-line)
- [bech32](https://github.com/input-output-hk/bech32/#bech32-command-line)

# Current Situation

The investigation on the issue began back in December 2020 and has been tracked mostly in [cardano-wallet#2395](https://github.com/input-output-hk/cardano-wallet/issues/2395) which itself came from [daedalus#1234](https://github.com/input-output-hk/daedalus/issues/1234). Both tickets actually mention several, different, issues reported by ada holders. The ongoing effort isn't about helping those who lost their recovery phrase / mnemonic sentence. For those, there is not much that can be done. 

There is however a group of user who reportedly mention being in possession of their old keystore, are able to use the Daedalus recovery feature to load their keystore and see their funds in Daedalus but are unable to _spend them_. We'll attempt to summarize the findings and various areas explored in this document, while keeping the effort going on different fronts to figure out a solution. 

## The KeyStore / 'secret.key' file

Before the introduction of recovery phrase (a.k.a mnemonic sentences), wallets in Cardano used to be attached to a keystore file, typically called `secret.key`. That file is a binary-encoded (CBOR) data structure which follows the following structure:

```cddl
TODO: KEYSTORE CDDL
```

To be continued...
