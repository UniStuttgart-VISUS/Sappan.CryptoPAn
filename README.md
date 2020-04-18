# Sappan.CryptoPAn
This project provides a .NET Standard implementation in C# of the [Crypto-PAn IP pseudonymisation algorithm](https://en.wikipedia.org/wiki/Crypto-PAn) developed for the [SAPPAN Horizon 2020 project](https://sappan-project.eu).

The implementation of the pseudonymisation is mostly based on Peter Haag's implementation for [nfdump](https://github.com/phaag/nfdump), but also provides a generalisation for IPv6 that passes the conformance tests of the implementations for [Python](https://github.com/keiichishima/yacryptopan) and [Go](https://github.com/Yawning/cryptopan). The library includes the deanonymsation routine from David Scott's Lucent Crypto-PAn implementation, which has also been extended to support IPv6.

## Projects
The Visual Studio solution contains three projects, **Sappan.CryptoPAn**, which is the actual library implementing the `Anyonmiser` class (we use the original wording although the algorithm does pseudonymisation in the GDPR sense). **Sappan.CryptoPAn.Test** implements a series of conformance tests for the `Anonymiser`. Finally, **jsonanonymiser** demostrates the use of the `Anonymiser` for processing IP addresses in JSON files.

## Building and testing
The Visual Studio solution should build right away in a Visual Studio 2019 installation with C# workload and support for .NET Core installed with all dependencies being installed from [Nuget](https://www.nuget.org). The tests are implemented using the C# testing framework for Visual Studio and can be run from the "Test" menu.

## Usage
Usage is straightforward by creating an instance of `Anonymiser` with a 32 byte long key of your choice. It is recommended disposing the `Anonymiser` after use to zero out the pad in main memory. The following snippet illustrates the use of the anonymiser.

```c#
using System;
using System.Net;
using Sappan.CryptoPAn;

using (var anonymiser = new Anonymiser("n1dn5emfcakghfo13nbsjfdk3mbuk83h")) {
    var actualIP = IPAddress.Parse("196.168.215.12");
    var pseudonymisedIP = anonymiser.Anonymise(actualIP);
    var recoveredIP =  anonymiser.Anonymise(pseudonymisedIP);
}
```

There are several overloads of the `Anonymise` method:
* `uint Anonymise4(uint address)` is the most literal translation of the nfdump implementation to C#. This method is only for regression tests as it works on the integral number representation of an IPv4 address, which has been deprecated in C#. Furthermore, it requires the IP address to be converted to host byte order before being used.
* Likewise, `byte[] Anonymise6(byte[] address)` is the most literal translation of the nfdump implementation to C#. It should not be used as I think the original version is not correct.
* `byte[] Anonymise(byte[] address)` is the primary implementation of Crypto-PAn which works on the raw network byte order bytes of an `IPAddress`. You can pass the result of `IPAddress.GetAddressBytes()` to the method. Theoretically, the method works on arbitrary address lengths up to 16 bytes. All input longer than 16 bytes is truncated as the cryptographic blocks used are only 16 bytes.
* `IPAddress Anonymise(IPAddress address)` is a convenience method that does the conversion to and from `byte` arrays for you.

Likewise, there are matching overloads of the `Deanonymise` method as well:
* `byte[] Deanonymise(byte[] address)` is the counterpart of `byte[] Anonymise(byte[] address)`, which uncovers the original IP provided the same cryptographic key is provided.
* Likewise, `IPAddress Deanonymise(IPAddress address)` is a convenience method that does the conversion to and from `byte` arrays for you.