dsniff
=================================================
Collection of tools for auditing and penetration testing.

What is dsniff?
-------------------------------------------------
Dsniff is originally developed by *Dug Song* for testing insecure
LAN. In his [personal page](http://www.monkey.org/~dugsong/dsniff)
There are many documents.

Why I rewrite it?
-------------------------------------------------
Dugsong never maintain dsniff for ten years and dsniff cannot compile
with libnet-1.1 later(but libnet-1.1 below is difficult to access now).
Moreover, some of tools are not available for hardware reasons.

As a result, I rewrite it with lastest dependency and maybe add some
new features(such as WLAN auditing tools) in the future.

Any issue or pull request are welcomed.

What is the state of this project?
--------------------------------------------------
Many part of origin dsniff are modified but I don't guarantee all of them
are correctly work well.

The following of them haved been tested and work well.
* arpspoof
* dnsspoof
* urlsnarf

