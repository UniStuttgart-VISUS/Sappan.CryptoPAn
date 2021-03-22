# Sappan.CryptoPAn
This project provides a .NET Standard implementation in C# of the [Crypto-PAn IP pseudonymisation algorithm](https://en.wikipedia.org/wiki/Crypto-PAn) developed for the [SAPPAN Horizon 2020 project](https://sappan-project.eu).

The implementation of the pseudonymisation is mostly based on Peter Haag's implementation for [nfdump](https://github.com/phaag/nfdump), but also provides a generalisation for IPv6 that passes the conformance tests of the implementations for [Python](https://github.com/keiichishima/yacryptopan) and [Go](https://github.com/Yawning/cryptopan). The library includes the deanonymsation routine from David Scott's Lucent Crypto-PAn implementation, which has also been extended to support IPv6.

## Projects
The Visual Studio solution contains three projects, **Sappan.CryptoPAn**, which is the actual library implementing the `Anyonmiser` class (we use the original wording although the algorithm does pseudonymisation in the GDPR sense). **Sappan.CryptoPAn.Test** implements a series of conformance tests for the `Anonymiser`. Finally, **jsonsanitiser** demostrates the use of the `Anonymiser` for processing IP addresses in JSON files.

## Building and testing
The Visual Studio solution should build right away in a Visual Studio 2019 installation with C# workload and support for .NET Core installed with all dependencies being installed from [Nuget](https://www.nuget.org). The tests are implemented using the C# testing framework for Visual Studio and can be run from the "Test" menu.

## Usage
### Sappan.CryptoPAn
Usage is straightforward by creating an instance of `Anonymiser` with a 32 byte long key of your choice. It is recommended disposing the `Anonymiser` after use to zero out the pad in main memory. The following snippet illustrates the use of the anonymiser.

```c#
using System;
using System.Net;
using Sappan.CryptoPAn;

using (var anonymiser = new Anonymiser("n1dn5emfcakghfo13nbsjfdk3mbuk83h")) {
    var actualIP = IPAddress.Parse("196.168.215.12");
    var pseudonymisedIP = anonymiser.Anonymise(actualIP);
    var recoveredIP =  anonymiser.Deanonymise(pseudonymisedIP);
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

### jsonsanitiser
The jsonsanitiser is controlled by a configuration file, which is passed as the only command line argument to the tool. The default configuration is as follows:

```js
{
    "CommandLineFields": {          // Fields to be interpreted as command lines.
        "Alphabet": "<ASCII>",      // Alphabet used for the output.
        "Paths": [],                // JSONPath expression to fields.
        "Scaling": 1                // Scaling factor for the string length.
    },
    "CryptoPAnKey": null,           // AES key and initial pad for Crypto-PAn (32 characters).
    "DestinationSuffix": ".anon",   // Suffix added to output files if "Inline" is not specified.
    "DomainNameFields": {           // Fields to be interpreted as domain names.
        "Alphabet": "abcdefghijklmnopqrstuvqxyz0123456789-",
        "Paths": [],                // JSONPath expression to fields.
        "Scaling": 1                // Scaling factor for the string length.
    },
    "EraseFields": [],              // JSONPath expression to fields recursively erased from the output.
    "FixedLengthStringFields": {    // Strings that will retain their original length.
        "Alphabet": "<ASCII>",      // Alphabet used for the output.
        "Paths": [],                // JSONPath expression to fields.
        "Scaling": 1                // Scaling factor for the string length.
    },
    "Inline": false,                // If true, replace the original file.
    "IPAddressFields": [],          // JSONPath expression to IP addresses pseudonymised with Crypto-PAn.
    "LineByLine": false,            // Force line-by-line processing and disable content probing.
    "MacAddressFields": [],         // JSONPath expression to MAC addresses pseudonymised with Crypto-PAn.
    "PathFields": {                 // Strings that will be interpreted as file system paths.
        "Alphabet": "<ASCII>",      // Alphabet used for the output.
        "Paths": [],                // JSONPath expression to fields.
        "Scaling": 1                // Scaling factor for the string length.
    },
    "Recurse": false,               // If the path specified is a directory, process all subdirectories.
    "ScaledStringFields": {         // Strings that will have a scaled output length.
        "Alphabet": "<ASCII>",      // Alphabet used for the output.
        "Paths": [],                // JSONPath expression to fields.
        "Scaling": 1                // Scaling factor for the string length.
    },
    "SearchPattern": "*",           // The search pattern for the files to be sanitised.
    "SourcePath": null,             // Path to a file or directory with data to be sanitised.
    "StringCryptoKey": null,        // AES key for pseudonymising strings.
}
```

## Acknowledgements
This project has received funding from the European Union’s Horizon 2020 research and innovation programme under grant agreement No. 833418.

