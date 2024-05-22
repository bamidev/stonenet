# Stonenet

Stonenet is a peer-to-peer (social) publish-subscribe network, also known as a
decentralized social media platform. It is designed to protect free speech and
resist censorship. It does this by putting all the data in the hands of the
people, rather than jsut one (or a handful) of servers like other centralized
and federated social networks. Everyone moderates their own home feed, and
content is only distributed by those peers that have consented to do so, by
subscribing to someone and thereby explicitly supporting their content.

Stonenet works because every participant in the network donates a certain amount
of disk space to those they follow. This resists censorship simply because it
results in a lot of data duplication of recent content, which should be ok since
disk space is very cheap nowadays.
Everyone that wants to help out the network even more than that, can put up
nodes on servers to help improve peer-to-peer connectivity and data
availability.

Moreover, cryptography in Stonenet ensures that nodes that choose to help with
relaying & data storage of random peers, will be unable to know what they are
relaying or storing. This provides ["plausible deniability"](https://en.wikipedia.org/wiki/Plausible_deniability#Use_in_computer_networks)
in the jurisdictions that support it.

You can even increase the reach of your content outside of the network. A
Stonenet node can be set up as a web-server or an ActivityPub server, so that
your content can be provided to non- Stonenet users on the World Wide Web & the
[Fediverse](https://en.wikipedia.org/wiki/Fediverse).

Otherwise, Stonenet just has a simple user interface mostly befitting of a
micro-blogging platform, but without any practical limits to what content you
can actually post.

**Note**: *Stonenet is still in early development. If you start using Stonenet,
keep your client up to date because it may otherwise become incompatible with
the rest of the network.*

See the doc/ABOUT page for more info.

![image alt center](desktop/assets/logo/128x128.png "Stonenet Logo") 
