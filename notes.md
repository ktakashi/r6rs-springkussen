Implementations notes
=====================

CSPRNG
------

At this moment, or even in the future, vanilla implementation of
`read-system-random!` doesn't work on Windows as it relay on the
random devices, such as `/dev/urandom`.  Also unfortunately,
R6RS Scheme doesn't have any time related procedures, this means
we can't diverse the random generator seed.

To make it work, we need to make the below file implementation specific:

- [`src/springkussen/random/system.sls`](src/springkussen/random/system.sls)

At this moment, the below implementations works on the platform which
they support:

- Sagittarius

