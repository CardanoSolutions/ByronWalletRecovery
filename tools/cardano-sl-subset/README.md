# cardano-sl (subset)

A tiny subset of the [cardano-sl](https://github.com/input-output-hk/cardano-sl/tree/v1.0.1) code base which compiles. The subset is focused on address and key derivation, to reproduce as much as possible the behavior of the legacy code. 

> Note that so far, the code is equivalent to the reboot implementation for Byron found in [cardano-ledger](https://github.com/input-output-hk/cardano-ledger).

## Installation

```
stack build cardano-sl-subset
```

## Example 

```
stack run cardano-sl-subset -- 58e430533eec06c33348e50d306528c1c53fe2dd774815b455ea062d4227e8496c00eb017ac85b60b2f68f2610d4045672a9d63703e6567b37e37008f97838edbb399d7d33f0a1433e8c7409ec139d0cb2cb83202795eab954010d57832c98456beda14fecc62bbedec11707ab671648316db677f6e5cd28aba85a04ca4a75b7 \
  2147483648 \
  2147483648 

DdzFFzCqrht8x5XWEGM9kGLd9oVrHByVsk5SZFG5MvmWf5Uc1H7DtSt76sF5eHztD7UHe8WF1Ccf1AeoAXcbJWS5hWy8bCDLpkDJQ6ex
```
