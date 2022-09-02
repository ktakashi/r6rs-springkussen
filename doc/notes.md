Implementations notes
=====================

Thread safety
-------------

The library is not meant to be thread safe, however certain components,
especially random generator, are not always explicitly passed to the
provided procedures. And it's rather annoying to do so as well. So,
we decided to implement some thread safety. However, mutexes are not
supported by R6RS and not all implementations supports SRFI-18 either.

To make the library works out-of-box without any modification, we
have a mechanism to check if the implementation supports SRFI-18 or not.
And if so, uses the procedures otherwise using dummy implementations.
See the `(springkussen misc lock)` library:

- [`src/springkussen/misc/lock.sls`](../src/springkussen/misc/lock.sls)

As far as I know, the current active implementations which don't support
SRFI-18 are actually only Chez Scheme. So, we put special treatment
for this as well.


CSPRNG
------

At this moment, or even in the future, vanilla implementation of
`read-system-random!` doesn't work on Windows as it relay on the
random devices, such as `/dev/urandom`.  Also unfortunately,
R6RS Scheme doesn't have any time related procedures, this means
we can't diverse the random generator seed.

To make it work, we need to make the below file implementation specific:

- [`src/springkussen/random/system.sls`](../src/springkussen/random/system.sls)

At this moment, the below implementations works on the platform which
they support:

- Sagittarius


Security consideration
======================

Iteration count of PBE
----------------------

By default the iteration count is `1024`. This might be a bit too small
comparing to modern cryptographic libraries. For example, Java JCE uses
`10000` to `100000`. The purpose for the small number is that not all
Scheme implementations are native compilers and using `100000` iteration
may end up over `200000000` loop of digest, which takes unbearable amount
of time to compute.


PKCS#12 keystore
----------------

PKCS#12 keystore allow us to create non encrypted content info. For example,
Java's SUN provider puts two content info containers, one for encrypted keys
and another one for certificates. It only encrypts the latter and the first
one are not encrypted as the content itself is encrypted.

We don't follow the above example, but we encrypt the entire content. In
this way, it doesn't show what kind of entry the keystore contains by 
dumping the ASN.1 format.
