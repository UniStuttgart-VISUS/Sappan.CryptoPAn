// <copyright file="Anonymiser.cs" company="Universität Stuttgart">
// Copyright © 2020 SAPPAN Consortium. All rights reserved.
// </copyright>
// <author>Christoph Müller</author>

using System;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;


namespace Sappan.CryptoPAn {

    /// <summary>
    /// Cryptography-based prefix-preserving anonymiser based on the
    /// implementation of Peter Haag
    /// (https://github.com/phaag/nfdump/blob/master/bin/panonymizer.c)
    /// used by CESNET's IPFIXcol.
    /// </summary>
    public sealed class Anonymiser : IDisposable {

        #region Public constructors
        /// <summary>
        /// Initialises a new instance with the typical Crypto-PAn Rijndael key
        /// and pad.
        /// </summary>
        /// <param name="key">The key (first 16 bytes) followed by the initial
        /// value of the pad (the second 16 bytes).</param>
        /// <exception cref="ArgumentNullException">If <paramref name="key"/>
        /// is <c>null</c>.</exception>
        /// <exception cref="ArgumentException">If <paramref name="key"/> is too
        /// short.</exception>
        public Anonymiser(byte[] key) : this(GetRijndael(key), GetPad(key)) {
            // Note: the following line erases the pad such that one can see the
            // bits shifted into the Rijndael buffer for debugging purposes.
            //for (int i = 0; i < this._pad.Length; ++i) this._pad[i] = 0;
        }

        /// <summary>
        /// Initialises a new instance with the typical Crypto-PAn Rijndael key
        /// and pad.
        /// </summary>
        /// <param name="key">The key string, which must comprise 32 ASCII
        /// characters. The first 16 characters are used as crypto key and the
        /// second 16 characters are the inital value of the pad.</param>
        /// <exception cref="ArgumentNullException">If <paramref name="key"/>
        /// is <c>null</c>.</exception>
        /// <exception cref="ArgumentException">If <paramref name="key"/> is too
        /// short.</exception>
        public Anonymiser(string key) : this(Encoding.ASCII.GetBytes(key)) { }
        #endregion

        #region Finaliser
        /// <summary>
        /// Finalises the instance.
        /// </summary>
        ~Anonymiser() {
            this.Dispose(false);
        }
        #endregion

        #region Public methods
        /// <summary>
        /// Pseudonymise an IP address given in network byte order.
        /// </summary>
        /// <param name="address">The IP address to be converted. If this array
        /// is larger that 16 bytes, all bytes after the 16th are ignores.
        /// </param>
        /// <returns>The pseudonymised IP address in network byte order.</returns>
        /// <exception cref="ArgumentNullException">If
        /// <paramref name="address"/> is <c>null</c>.</exception>
        public byte[] Anonymise(byte[] address) {
            if (address == null) {
                throw new ArgumentNullException(nameof(address));
            }

            var cryptoOutput = new byte[this._pad.Length];
            var cryptoInput = new byte[this._pad.Length];
            var length = Math.Min(16, address.Length);
            var retval = Enumerable.Repeat((byte) 0, length).ToArray();

            // Restart with the initial padding for each input and make sure
            // that the trailing bytes of the pad, which are never modified, are
            // set correctly.
            Array.Copy(this._pad, cryptoInput, cryptoInput.Length);

            for (int pos = 0; pos < length * 8; ++pos) {
                var bit = pos & 0x7;
                var index = pos >> 3;

                if (pos > 0) {
                    // Copy all full address bytes.
                    for (var i = 0; i < index; ++i) {
                        cryptoInput[i] = address[i];
                    }

                    // The 'index'th byte is partially filled from the address
                    // and the padding.
                    var mask = (byte) (0xFF << (8 - bit));
                    var addrBits = address[index] & mask;
                    var padBits = this._pad[index] & ~mask;
                    cryptoInput[index] = (byte) (addrBits | padBits);

                    // Fill the rest from the pad.
                    for (var i = index + 1; i < address.Length; ++i) {
                        cryptoInput[i] = this._pad[i];
                    }
                }

                // Perform the crypto transform.
                this._cryptoTransform.TransformBlock(cryptoInput, 0,
                    cryptoInput.Length, cryptoOutput, 0);

                // Combine the bits into the one-time-pad.
                retval[index] |= (byte) ((cryptoOutput[0] >> 7) << (7 - bit));
            }

            // XOR the orginal address with the pseudorandom one-time-pad.
            for (int i = 0; i < retval.Length; ++i) {
                retval[i] ^= address[i];
            }

            return retval;
        }

        /// <summary>
        /// Pseudonymise an IP address given in network byte order.
        /// </summary>
        /// <param name="address">The bytes of the IP address, which must have
        /// the minimum size for the specified <see cref="AddressFamily"/>. If
        /// there are more bytes than expected, these are ignored.</param>
        /// <param name="family"></param>
        /// <returns>The pseudonymised IP address in network byte order.
        /// </returns>
        /// <exception cref="ArgumentNullException">If
        /// <paramref name="address"/> is <c>null</c>.</exception>
        /// <exception cref="ArgumentException">If <paramref name="address"/>
        /// is too short for the specified <see cref="AddressFamily"/>.
        /// </exception>
        /// <exception cref="ArgumentException">If <paramref name="family"/>
        /// is any other than <see cref="AddressFamily.InterNetwork"/> or
        /// <see cref="AddressFamily.InterNetworkV6"/>.</exception>
        public byte[] Anonymise(byte[] address, AddressFamily family) {
            if (address == null) {
                throw new ArgumentNullException(nameof(address));
            }

            switch (family) {
                case AddressFamily.InterNetwork:
                    return this.Anonymise4(address);

                case AddressFamily.InterNetworkV6:
                    if (address.Length < 16) {
                        throw new ArgumentException(
                            Properties.Resources.ErrorIPv6TooShort,
                            nameof(address));
                    }
                    return this.Anonymise(address);

                default:
                    throw new ArgumentException(
                        Properties.Resources.ErrorUnsupportedFamily,
                        nameof(family));
            }
        }

        /// <summary>
        /// Pseudonymise an IP address.
        /// </summary>
        /// <param name="address">The IP address to be pseudonomised.</param>
        /// <returns>The pseudonymised IP address in network byte order.
        /// </returns>
        /// <exception cref="ArgumentNullException">If
        /// <paramref name="address"/> is <c>null</c>.</exception>
        /// <exception cref="ArgumentException">If <paramref name="address"/>
        /// has an unsupported <see cref="AddressFamily"/>.</exception>
        public IPAddress Anonymise(IPAddress address) {
            var bytes = this.Anonymise(address?.GetAddressBytes(),
                address?.AddressFamily ?? AddressFamily.Unspecified);
            return new IPAddress(bytes);
        }

        /// <summary>
        /// Pseudonymise an IPv4 address.
        /// </summary>
        /// <remarks>
        /// <para>This is the most literal translation of the original C++
        /// implementation.</para>
        /// <para>Note that this implementation works on an addess in host byte
        /// order, but the <see cref="IPAddress"/> answers its value in network
        /// byte order. A conversion is therefore necessary to achieve the
        /// correct result.</para>
        /// </remarks>
        /// <param name="address">The address to be anonymised, which is assumed
        /// to be in host byte order.</param>
        /// <returns>The pseudonymised address.</returns>
        [Obsolete("The reference implementation is only intended for "
            + "regression tests.")]
        public uint Anonymise4(uint address) {
            Debug.Assert(this._pad != null);
            Debug.Assert(this._pad.Length >= 4);
            var rin_output = new byte[this._pad.Length];
            var rin_input = new byte[this._pad.Length];
            uint retval = 0;

            uint first4bytes_input;

            // Start over with the user-defined pad for each address.
            Array.Copy(this._pad, rin_input, rin_input.Length);
            //memcpy(rin_input, m_pad, 16);

            var first4bytes_pad = (((uint) this._pad[0]) << 24)
                + (((uint) this._pad[1]) << 16)
                + (((uint) this._pad[2]) << 8)
                + (uint) this._pad[3];

            // For each prefixes with length from 0 to 31, generate a bit using
            // the Rijndael cipher, which is used as a pseudorandom function
            // here. The bits generated in every rounds are combineed into a
            // pseudorandom one-time-pad.
            for (int pos = 0; pos <= 31; pos++) {
                // Padding: The most significant pos bits are taken from
                // orig_addr. The other 128-pos bits are taken from m_pad. The
                // variables first4bytes_pad and first4bytes_input are used to
                // handle the annoying byte order problem.
                if (pos == 0) {
                    first4bytes_input = first4bytes_pad;
                } else {
                    first4bytes_input = ((address >> (32 - pos)) << (32 - pos))
                        | ((first4bytes_pad << pos) >> pos);
                }

                rin_input[0] = (byte) (first4bytes_input >> 24);
                rin_input[1] = (byte) ((first4bytes_input << 8) >> 24);
                rin_input[2] = (byte) ((first4bytes_input << 16) >> 24);
                rin_input[3] = (byte) ((first4bytes_input << 24) >> 24);

                //Debug.WriteLine(string.Join("-", rin_input.Select(b => b.ToString("x"))));

                // Encryption: The Rijndael cipher is used as pseudorandom
                // function. During each round, only the first bit of
                // rin_output is used.
                //Rijndael_blockEncrypt(rin_input, 128, rin_output);
                this._cryptoTransform.TransformBlock(rin_input, 0,
                    rin_input.Length, rin_output, 0);

                //Debug.WriteLine(string.Join("-", rin_output.Select(b => b.ToString("x"))));
                //Debug.WriteLine($"{rin_output[0]} {rin_output[0] >> 7}");
                //Debug.WriteLine($"{((rin_output[0]) >> 7) << (31 - pos)}");

                // Combination: the bits are combined into a pseudorandom
                // one-time-pad
                retval |= (uint) (((rin_output[0]) >> 7) << (31 - pos));
            }

            // XOR the orginal address with the pseudorandom one-time-pad.
            retval = retval ^ address;

            return retval;
        }

        /// <summary>
        /// Pseudonymise an IPv4 address given in network byte order.
        /// </summary>
        /// <param name="address">The IP address to be converted. If this
        /// array is larger than four bytes, the first four are interpreted
        /// as the address.</param>
        /// <returns>The pseudonymised IP address in network byte order.</returns>
        /// <exception cref="ArgumentNullException">If
        /// <paramref name="address"/> is <c>null</c>.</exception>
        /// <exception cref="ArgumentException">If <paramref name="address"/>
        /// comprises less than four bytes.</exception>
        public byte[] Anonymise4(byte[] address) {
            if (address == null) {
                throw new ArgumentNullException(nameof(address));
            }
            if (address.Length < 4) {
                throw new ArgumentException(
                    Properties.Resources.ErrorIPv4TooShort,
                    nameof(address));
            }

            var cryptoOutput = new byte[this._pad.Length];
            var cryptoInput = new byte[this._pad.Length];
            var retval = Enumerable.Repeat((byte) 0, 4).ToArray();

            // Restart with the initial padding for each input and make sure
            // that the trailing bytes of the pad, which are never modified, are
            // set correctly.
            Array.Copy(this._pad, cryptoInput, cryptoInput.Length);

            for (int pos = 0; pos < 32; ++pos) {
                var bit = pos & 0x7;
                var index = pos >> 3;

                if (pos > 0) {
                    // Copy all full address bytes.
                    for (var i = 0; i < index; ++i) {
                        cryptoInput[i] = address[i];
                    }

                    // The 'index'th byte is partially filled from the address
                    // and the padding.
                    var mask = (byte) (0xFF << (8 - bit));
                    var addrBits = address[index] & mask;
                    var padBits = this._pad[index] & ~mask;
                    cryptoInput[index] = (byte) (addrBits | padBits);

                    // Fill the rest from the pad.
                    for (var i = index + 1; i < address.Length; ++i) {
                        cryptoInput[i] = this._pad[i];
                    }
                }

                //Debug.WriteLine(string.Join("-", cryptoInput.Select(b => b.ToString("x"))));

                // Perform the crypto transform.
                this._cryptoTransform.TransformBlock(cryptoInput, 0,
                    cryptoInput.Length, cryptoOutput, 0);

                //Debug.WriteLine(string.Join("-", cryptoOutput.Select(b => b.ToString("x"))));
                //Debug.WriteLine($"{cryptoOutput[0]} {cryptoOutput[0] >> 7}");
                //Debug.WriteLine($"{(cryptoOutput[0] >> 7) << (7 - bit)}");

                // Combine the bits into the one-time-pad.
                retval[index] |= (byte) ((cryptoOutput[0] >> 7) << (7 - bit));
            }

            // XOR the orginal address with the pseudorandom one-time-pad.
            for (int i = 0; i < retval.Length; ++i) {
                retval[i] ^= address[i];
            }

            return retval;
        }

        /// <summary>
        /// Pseudonymise an IPv6 address.
        /// </summary>
        /// <remarks>
        /// <para>This is the most literal translation of the original C++
        /// implementation.</para>
        /// <para>Note that this implementation looks a bit shady and is only
        /// there for compatibility with the code used in IPFIXcol.</para>
        /// </remarks>
        /// <param name="address">The address to be anonymised.</param>
        /// <returns>The pseudonymised address.</returns>
        /// <exception cref="ArgumentNullException">If
        /// <paramref name="address"/> is <c>null</c>.</exception>
        /// <exception cref="ArgumentException">If <paramref name="address"/>
        /// comprises less than 16 bytes.</exception>
        [Obsolete("I think this algorithm is just wrong.")]
        public byte[] Anonymise6(byte[] address) {
            if (address == null) {
                throw new ArgumentNullException(nameof(address));
            }
            if (address.Length < 16) {
                throw new ArgumentException(
                    Properties.Resources.ErrorIPv6TooShort,
                    nameof(address));
            }

            var anon_addr = new byte[16];
            var rin_output = new byte[16];
            var rin_input = new byte[16];

            anon_addr[0] = anon_addr[1] = 0;

            // For each prefixes with length from 0 to 127, generate a bit using
            // the Rijndael cipher, which is used as a pseudorandom function
            // here. The bits generated in every rounds are combineed into a
            // pseudorandom one-time-pad.
            for (int pos = 0; pos <= 127; pos++) {
                var bit_num = pos & 0x7;
                var left_byte = (pos >> 3);

                for (int i = 0; i < left_byte; i++) {
                    rin_input[i] = address[i];
                }

                rin_input[left_byte] = (byte)
                    (address[left_byte] >> (7 - bit_num) << (7 - bit_num)
                    | (this._pad[left_byte] << bit_num) >> bit_num);

                for (int i = left_byte + 1; i < 16; i++) {
                    rin_input[i] = this._pad[i];
                }

                // Encryption: The Rijndael cipher is used as pseudorandom
                // function. During each round, only the first bit of
                // rin_output is used.
                //Rijndael_blockEncrypt(rin_input, 128, rin_output);
                this._cryptoTransform.TransformBlock(rin_input, 0,
                    rin_input.Length, rin_output, 0);

                // Combination: the bits are combined into a pseudorandom
                // one-time-pad.
                anon_addr[left_byte] |= (byte) ((rin_output[0] >> 7) << bit_num);
            }

            // XOR the orginal address with the pseudorandom one-time-pad
            for (int i = 0; i < anon_addr.Length; ++i) {
                anon_addr[i] ^= address[i];
            }

            return anon_addr;
        }

        /// <summary>
        /// Provided that the original key is set in the anonymiser, undo the
        /// pseudonomisation of the given address in network byte order.
        /// </summary>
        /// <remarks>
        /// This is method is a generalisation of David Stott's Lucent
        /// Crypto-PAn implementation.
        /// </remarks>
        /// <param name="address">The address to be uncovered. If the address
        /// is longer than 16 bytes (IPv6), all subsequent bytes are ignored.
        /// </param>
        /// <param name="length">The number of bytes of
        /// <paramref name="address"/> to be used. If this is larger than
        /// the actual size of <paramref name="address"/> or less than or equal
        /// to zero, it will be clamped to the size.</param>
        /// <returns>The original address</returns>
        /// <exception cref="ArgumentNullException">If
        /// <paramref name="address"/> is <c>null</c>.</exception>
        public byte[] Deanonymise(byte[] address, int length = 0) {
            if (address == null) {
                throw new ArgumentNullException(nameof(address));
            }

            if (length <= 0) {
                length = address.Length;
            }
            if (length > KeySize) {
                length = KeySize;
            }

            var cryptoOutput = new byte[this._pad.Length];
            var cryptoInput = new byte[this._pad.Length];
            var retval = new byte[length];

            // Initialise the output. We create a copy in order to keep the
            // input unmodified.
            Array.Copy(address, 0, retval, 0, length);

            // Restart with the initial padding for each input and make sure
            // that the trailing bytes of the pad, which are never modified, are
            // set correctly.
            Array.Copy(this._pad, cryptoInput, cryptoInput.Length);

            for (int pos = 0; pos < length * 8; ++pos) {
                var bit = pos & 0x7;
                var index = pos >> 3;

                if (pos > 0) {
                    // Copy all full address bytes.
                    for (var i = 0; i < index; ++i) {
                        cryptoInput[i] = retval[i];
                    }

                    // The 'index'th byte is partially filled from the address
                    // and the padding.
                    var mask = (byte) (0xFF << (8 - bit));
                    var addrBits = retval[index] & mask;
                    var padBits = this._pad[index] & ~mask;
                    cryptoInput[index] = (byte) (addrBits | padBits);

                    // Fill the rest from the pad.
                    for (var i = index + 1; i < retval.Length; ++i) {
                        cryptoInput[i] = this._pad[i];
                    }
                }

                // Perform the crypto transform.
                this._cryptoTransform.TransformBlock(cryptoInput, 0,
                    cryptoInput.Length, cryptoOutput, 0);

                // Combine the bits into the one-time-pad.
                retval[index] ^= (byte) ((cryptoOutput[0] >> 7) << (7 - bit));
            }

            return retval;
        }

        /// <summary>
        /// Provided that the original key is set in the anonymiser, undo the
        /// pseudonomisation of the given address.
        /// </summary>
        /// <param name="address">The address to be uncovered.</param>
        /// <returns>The original address.</returns>
        /// <exception cref="ArgumentNullException">If
        /// <paramref name="address"/> is <c>null</c>.</exception>
        public IPAddress Deanonymise(IPAddress address) {
            var bytes = this.Anonymise(address?.GetAddressBytes());
            return new IPAddress(bytes);
        }

        /// <inheritdoc />
        public void Dispose() {
            this.Dispose(true);
            GC.SuppressFinalize(this);
        }
        #endregion

        #region Private class methods
        private static byte[] GetPad(byte[] key) {
            _ = key ?? throw new ArgumentNullException(nameof(key));
            return key.Skip(KeySize).Take(KeySize).ToArray();
        }

        private static Rijndael GetRijndael(byte[] key) {
            if (key == null) {
                throw new ArgumentNullException(nameof(key));
            }
            if (key.Length < KeySize) {
                throw new ArgumentException(
                    Properties.Resources.ErrorKeyTooShort,
                    nameof(key));
            }

            var retval = Rijndael.Create();
            retval.Mode = CipherMode.ECB;
            retval.KeySize = KeySize * 8;   // Order of KeySize and Key matters!
            retval.Key = key.Take(KeySize).ToArray();
            retval.IV = Enumerable.Repeat((byte) 0, KeySize).ToArray();

            return retval;
        }
        #endregion

        #region Private constructors
        /// <summary>
        /// Initialise a new instance using the given Rijndael algorithm for
        /// generating random keys.
        /// </summary>
        /// <param name="rijndael">The Rijndael encryption algorithm, which
        /// must have been initialised with a key and an initial vector.
        /// </param>
        /// <param name="pad">The inital value of the one-time-pad, which must
        /// have the same size as the key of <paramref name="rijndael"/>.
        /// </param>
        /// <exception cref="ArgumentNullException">If
        /// <paramref name="rijndael"/> is <c>null</c>.</exception>
        /// <exception cref="ArgumentNullException">If <paramref name="pad"/>
        /// is <c>null</c>.</exception>
        /// <exception cref="ArgumentException">If <paramref name="rijndael"/>
        /// has no key.</exception>
        /// <exception cref="ArgumentException">If <paramref name="rijndael"/>
        /// has no initial vector.</exception>
        /// <exception cref="ArgumentException">If <paramref name="pad"/> has
        /// not the expected length.</exception>
        private Anonymiser(Rijndael rijndael, byte[] pad) {
            this._cryptoAlgorithm = rijndael
                ?? throw new ArgumentNullException(nameof(rijndael));
            _ = pad ?? throw new ArgumentNullException(nameof(pad));

            if ((rijndael.Key == null) || (rijndael.Key.Length <= 0)) {
                throw new ArgumentException(
                    Properties.Resources.ErrorNoKey,
                    nameof(rijndael));
            }
            if ((rijndael.IV == null) || (rijndael.IV.Length <= 0)) {
                throw new ArgumentException(
                    Properties.Resources.ErrorNoIV,
                    nameof(rijndael));
            }
            if (rijndael.KeySize != pad.Length * 8) {
                throw new ArgumentException(
                    Properties.Resources.ErrorPadLength,
                    nameof(pad));
            }

            // Create the Rijndael encryptor.
            this._cryptoTransform = rijndael.CreateEncryptor();

            // Allocate the secret pad.
            this._pad = new byte[pad.Length];

            // Initialise the 128-bit secret pad. The pad is encrypted before
            // being used for padding.
            this._cryptoTransform.TransformBlock(pad, 0, pad.Length,
                this._pad, 0);
        }
        #endregion

        #region Private methods
        private void Dispose(bool disposing) {
            if (this._cryptoTransform != null) {
                Debug.Assert(this._cryptoAlgorithm != null);
                if (disposing) {
                    this._cryptoAlgorithm.Dispose();
                    this._cryptoTransform.Dispose();
                }

                this._cryptoAlgorithm = null;
                this._cryptoTransform = null;

                // Clear the pad from memory as well ...
                Debug.Assert(this._pad != null);
                for (int i = 0; i < this._pad.Length; ++i) {
                    this._pad[i] = 0;
                }
            }
        }
        #endregion

        #region Private fields
        /// <summary>
        /// The size of the original Crytpo-PAn key in bytes.
        /// </summary>
        private const int KeySize = 16;

        /// <summary>
        /// The cryptographic algorithm that <see cref="_cryptoTransform"/> is
        /// derived from.
        /// </summary>
        /// <returns></returns>
        private SymmetricAlgorithm _cryptoAlgorithm;

        /// <summary>
        /// The cryptographic transform used as pseudorandom function.
        /// </summary>
        private ICryptoTransform _cryptoTransform;

        /// <summary>
        /// The initial state of the cryptographic one-time pad.
        /// </summary>
        private readonly byte[] _pad;
        #endregion
    }
}
