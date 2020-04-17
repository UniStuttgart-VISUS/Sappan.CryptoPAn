// <copyright file="AnonymiserTest.cs" company="Universität Stuttgart">
// Copyright © 2020 SAPPAN Consortium. All rights reserved.
// </copyright>
// <author>Christoph Müller</author>

using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Net;


namespace Sappan.CryptoPAn.Test {

    /// <summary>
    /// Tests for the Crypto-PAn <see cref="Anonymiser" />.
    /// </summary>
    [TestClass]
    public class AnonymiserTest {

        #region Test data
        public static readonly Dictionary<string, string> IPv4 = new Dictionary<string, string> {
            //{"255.255.255.255", "135.242.180.132"},
            // Test cases from https://github.com/Yawning/cryptopan/blob/master/cryptopan_test.go
            {"128.11.68.132", "135.242.180.132"},
            {"129.118.74.4", "134.136.186.123"},
            {"130.132.252.244", "133.68.164.234"},
            {"141.223.7.43", "141.167.8.160"},
            {"141.233.145.108", "141.129.237.235"},
            {"152.163.225.39", "151.140.114.167"},
            {"156.29.3.236", "147.225.12.42"},
            {"165.247.96.84", "162.9.99.234"},
            {"166.107.77.190", "160.132.178.185"},
            {"192.102.249.13", "252.138.62.131"},
            {"192.215.32.125", "252.43.47.189"},
            {"192.233.80.103", "252.25.108.8"},
            {"192.41.57.43", "252.222.221.184"},
            {"193.150.244.223", "253.169.52.216"},
            {"195.205.63.100", "255.186.223.5"},
            {"198.200.171.101", "249.199.68.213"},
            {"198.26.132.101", "249.36.123.202"},
            {"198.36.213.5", "249.7.21.132"},
            {"198.51.77.238", "249.18.186.254"},
            {"199.217.79.101", "248.38.184.213"},
            {"202.49.198.20", "245.206.7.234"},
            {"203.12.160.252", "244.248.163.4"},
            {"204.184.162.189", "243.192.77.90"},
            {"204.202.136.230", "243.178.4.198"},
            {"204.29.20.4", "243.33.20.123"},
            {"205.178.38.67", "242.108.198.51"},
            {"205.188.147.153", "242.96.16.101"},
            {"205.188.248.25", "242.96.88.27"},
            {"205.245.121.43", "242.21.121.163"},
            {"207.105.49.5", "241.118.205.138"},
            {"207.135.65.238", "241.202.129.222"},
            {"207.155.9.214", "241.220.250.22"},
            {"207.188.7.45", "241.255.249.220"},
            {"207.25.71.27", "241.33.119.156"},
            {"207.33.151.131", "241.1.233.131"},
            {"208.147.89.59", "227.237.98.191"},
            {"208.234.120.210", "227.154.67.17"},
            {"208.28.185.184", "227.39.94.90"},
            {"208.52.56.122", "227.8.63.165"},
            {"209.12.231.7", "226.243.167.8"},
            {"209.238.72.3", "226.6.119.243"},
            {"209.246.74.109", "226.22.124.76"},
            {"209.68.60.238", "226.184.220.233"},
            {"209.85.249.6", "226.170.70.6"},
            {"212.120.124.31", "228.135.163.231"},
            {"212.146.8.236", "228.19.4.234"},
            {"212.186.227.154", "228.59.98.98"},
            {"212.204.172.118", "228.71.195.169"},
            {"212.206.130.201", "228.69.242.193"},
            {"216.148.237.145", "235.84.194.111"},
            {"216.157.30.252", "235.89.31.26"},
            {"216.184.159.48", "235.96.225.78"},
            {"216.227.10.221", "235.28.253.36"},
            {"216.254.18.172", "235.7.16.162"},
            {"216.32.132.250", "235.192.139.38"},
            {"216.35.217.178", "235.195.157.81"},
            {"24.0.250.221", "100.15.198.226"},
            {"24.13.62.231", "100.2.192.247"},
            {"24.14.213.138", "100.1.42.141"},
            {"24.5.0.80", "100.9.15.210"},
            {"24.7.198.88", "100.10.6.25"},
            {"24.94.26.44", "100.88.228.35"},
            {"38.15.67.68", "64.3.66.187"},
            {"4.3.88.225", "124.60.155.63"},
            {"63.14.55.111", "95.9.215.7"},
            {"63.195.241.44", "95.179.238.44"},
            {"63.97.7.140", "95.97.9.123"},
            {"64.14.118.196", "0.255.183.58"},
            {"64.34.154.117", "0.221.154.117"},
            {"64.39.15.238", "0.219.7.41"},

            // Test cases obtained from C++ implementation
            { "129.69.205.36", "134.182.53.212" },
            { "129.69.215.37", "134.182.41.43" },
            { "127.0.0.1", "33.0.243.129" },
        };

        public static readonly Dictionary<string, string> IPv6 = new Dictionary<string, string> {
                // Test cases from https://github.com/Yawning/cryptopan/blob/master/cryptopan_test.go
                { "::1", "78ff:f001:9fc0:20df:8380:b1f1:704:ed"},
                { "::2", "78ff:f001:9fc0:20df:8380:b1f1:704:ef"},
                { "::ffff", "78ff:f001:9fc0:20df:8380:b1f1:704:f838"},
                { "2001:db8::1", "4401:2bc:603f:d91d:27f:ff8e:e6f1:dc1e"},
                { "2001:db8::2", "4401:2bc:603f:d91d:27f:ff8e:e6f1:dc1c"},
            };

        public static readonly byte[] Key = new byte[] {
            21, 34, 23, 141,
            51, 164, 207, 128,
            19, 10, 91, 22,
            73,  144, 125, 16,

            216, 152, 143, 131,
            121, 121, 101, 39,
            98, 87, 76, 45,
            42, 132, 34, 2
        };
        #endregion

        [TestMethod]
        public void TestReference4() {
            using (var anonymiser = new Anonymiser(Key)) {
                foreach (var t in IPv4) {
                    var address = IPAddress.Parse(t.Key).GetAddressBytes();
                    var input = BitConverter.ToUInt32(address, 0);
                    input = (uint) IPAddress.NetworkToHostOrder((int) input);

#pragma warning disable CS0618
                    var output = anonymiser.Anonymise4(input);
#pragma warning restore CS0618
                    output = (uint) IPAddress.HostToNetworkOrder((int) output);
                    var actual = new IPAddress(output);

                    var expected = IPAddress.Parse(t.Value);
                    Assert.AreEqual(expected, actual);
                }
            }
        }

        [TestMethod]
        public void TestBytes4() {
            using (var anonymiser = new Anonymiser(Key)) {
                foreach (var t in IPv4) {
                    var input = IPAddress.Parse(t.Key).GetAddressBytes();
                    var output = anonymiser.Anonymise4(input);
                    var actual = new IPAddress(output);
                    var expected = IPAddress.Parse(t.Value);
                    Assert.AreEqual(expected, actual);
                }
            }
        }

        //[TestMethod]
        //public void TestReference6() {
        //    using (var anonymiser = new Anonymiser(Key)) {
        //        foreach (var t in IPv6) {
        //            var input = IPAddress.Parse(t.Key).GetAddressBytes();
        //            var output = anonymiser.Anonymise6(input);
        //            var actual = new IPAddress(output);
        //            var expected = IPAddress.Parse(t.Value);
        //            Assert.AreEqual(expected, actual);
        //        }
        //    }
        //}

        [TestMethod]
        public void TestBytes6() {
            using (var anonymiser = new Anonymiser(Key)) {
                foreach (var t in IPv6) {
                    var input = IPAddress.Parse(t.Key).GetAddressBytes();
                    var output = anonymiser.Anonymise(input);
                    var actual = new IPAddress(output);
                    var expected = IPAddress.Parse(t.Value);
                    Assert.AreEqual(expected, actual);
                }
            }
        }

        [TestMethod]
        public void TestBytes64() {
            using (var anonymiser = new Anonymiser(Key)) {
                foreach (var t in IPv4) {
                    var input = IPAddress.Parse(t.Key).GetAddressBytes();
                    var output = anonymiser.Anonymise(input);
                    var actual = new IPAddress(output);
                    var expected = IPAddress.Parse(t.Value);
                    Assert.AreEqual(expected, actual);
                }
            }
        }

        [TestMethod]
        public void TestIPAddress4() {
            using (var anonymiser = new Anonymiser(Key)) {
                foreach (var t in IPv4) {
                    var input = IPAddress.Parse(t.Key);
                    var actual = anonymiser.Anonymise(input);
                    var expected = IPAddress.Parse(t.Value);
                    Assert.AreEqual(expected, actual);
                }
            }
        }

        [TestMethod]
        public void TestIPAddress6() {
            using (var anonymiser = new Anonymiser(Key)) {
                foreach (var t in IPv6) {
                    var input = IPAddress.Parse(t.Key);
                    var actual = anonymiser.Anonymise(input);
                    var expected = IPAddress.Parse(t.Value);
                    Assert.AreEqual(expected, actual);
                }
            }
        }

        [TestMethod]
        public void TestStringKey() {
            using (var anonymiser = new Anonymiser("n1dn5emfcakghfo13nbsjfdk3mbuk83h")) {
                var input = IPAddress.Parse("129.69.205.36");
                var actual = anonymiser.Anonymise(input);
                var expected = IPAddress.Parse("97.2.50.215");
                Assert.AreEqual(expected, actual);
            }
        }

    }
}
