# How to Contribute

## Tell Your Story

If you've been around during the early days of Cardano (September 2017 → December 2017) and remember details about the steps you went through for redeeming your genesis funds, about versions of the software you used etc.. If you still have your old database and keystore around, make sure to keep them safe as they could turn very useful to experiment and extract information. 

Have a story to tell? Please start a [Github Discussion](https://github.com/CardanoSolutions/ByronWalletRecovery/discussions). 

## Investigate 

If you have the necessary technical skills, dig in. There's a lot to dig in but it's mostly happening in:

- [input-output-hk/cardano-sl](https://github.com/input-output-hk/cardano-sl/tree/v1.0.1)
- [input-output-hk/cardano-crypto](https://github.com/input-output-hk/cardano-crypto/tree/1cde8e3a8d9093bbf571085920045c05edb3eaa4)
- [input-output-hk/daedalus](https://github.com/input-output-hk/daedalus/tree/0.8.0)

> **Warning:** Pay attention to versions and commit revisions. Issues with old Byron wallets seem to relate to wallets prior to 2018. So, while it may be useful to look at more modern versions of those codebases as comparison, the issue is in all likelihood present in those old versions.

At this stage, reviewing old code and trying to build and understanding of how some users may have end up in the situation they're in. If you find anything new or want to make a correction, please open a [Pull Request](https://github.com/CardanoSolutions/ByronWalletRecovery/pulls) and modify the main `README.md` with your findings. New tools and scripts are also welcome.

## Review 

Since the content and scripts of this repository are quite sensitive, we do need extra scrutiny of every contribution and any content that end up being merged in the main branch to avoid some ill-intentioned actor to submit malicious scripts or content that could harm ada holders seeking help. 
