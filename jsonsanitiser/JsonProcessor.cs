// <copyright file="JsonProcessor.cs" company="Universität Stuttgart">
// Copyright © 2020 SAPPAN Consortium. All rights reserved.
// </copyright>
// <author>Christoph Müller</author>

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Sappan.CryptoPAn;
using System;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Net;
using System.Net.NetworkInformation;
using System.Threading;
using System.Threading.Tasks;


namespace Sappan.JsonSanitiser {

    /// <summary>
    /// Implements the processing of the JSON data of a single file.
    /// </summary>
    internal sealed class JsonProcessor {

        /// <summary>
        /// Initialises a new instance.
        /// </summary>
        /// <param name="configuration"></param>
        /// <param name="anonymiser"></param>
        /// <param name="stringScrambler"></param>
        /// <param name="writer"></param>
        public JsonProcessor(Configuration configuration,
                Anonymiser anonymiser, StringScrambler stringScrambler,
                TextWriter writer) {
            this._anonymiser = anonymiser
                ?? throw new ArgumentNullException(nameof(anonymiser));
            this._configuration = configuration
                ?? throw new ArgumentNullException(nameof(configuration));
            this._stringScrambler = stringScrambler
                ?? throw new ArgumentNullException(nameof(stringScrambler));
            this._writer = writer;
        }

        /// <summary>
        /// Process the JSON file at <paramref name="inputPath"/> and store the
        /// anonymised version to <paramref name="outputPath"/>.
        /// </summary>
        /// <param name="inputPath"></param>
        /// <param name="outputPath"></param>
        public void Process(string inputPath, string outputPath) {
            this.WriteOutput(Properties.Resources.MsgProcessingFile,
                inputPath, outputPath);

            using (var fr = File.Open(inputPath, FileMode.Open,
                FileAccess.Read, FileShare.Read))
            using (var sr = new StreamReader(fr))
            using (var jr = new JsonTextReader(sr))
            using (var fw = File.Open(outputPath, FileMode.Create,
                FileAccess.Write, FileShare.Read))
            using (var sw = new StreamWriter(fw))
            using (var jw = new JsonTextWriter(sw)) {
                var serialiser = new JsonSerializer();

                // Read the stuff and decide based on the token returned whether
                // the file contains a valid JSON array or must be processed
                // line-by-line.
                var data = serialiser.Deserialize<JToken>(jr);

                if (data is JArray array) {
                    // Pseudonymise each element in the array and write it back.
                    this.WriteOutput(Properties.Resources.MsgProcessArray,
                        inputPath);
                    foreach (JObject record in array) {
                        this.ProcessRecord(record);
                    }
                    serialiser.Serialize(jw, data);

                } else {
                    // This must be processed line-by-line, so reset the stream
                    // and retry. Note it is important to discard any buffered
                    // data in the stream reader, because this would be
                    // processed again by ProcessLines().
                    this.WriteOutput(Properties.Resources.MsgProcessLineByLine,
                        inputPath);
                    fr.Seek(0, SeekOrigin.Begin);
                    sr.DiscardBufferedData();
                    this.ProcessLines(sr, sw);
                }
            }

            if (this._configuration.Inline) {
                this.WriteOutput(Properties.Resources.MsgReplaceSource,
                    inputPath);
                File.Delete(inputPath);
                File.Move(outputPath, inputPath);
            }
        }

        /// <summary>
        /// Process the JSON file at <paramref name="inputPath"/> and store the
        /// anonymised version to <paramref name="outputPath"/>.
        /// </summary>
        /// <param name="inputPath"></param>
        /// <param name="outputPath"></param>
        /// <returns></returns>
        public Task ProcessAsync(string inputPath, string outputPath) {
            return Task.Factory.StartNew(() => {
                this.Process(inputPath, outputPath);
            }, CancellationToken.None, TaskCreationOptions.LongRunning,
                TaskScheduler.Default);
        }

        /// <summary>
        /// Perform the configured transforms.
        /// </summary>
        /// <returns></returns>
        public async Task ProcessAsync() {
            if (Directory.Exists(this._configuration.SourcePath)) {
                this.WriteOutput(Properties.Resources.MsgProcessingDirectory,
                    this._configuration.SourcePath,
                    this._configuration.SearchPattern);

                var files = Directory.GetFiles(this._configuration.SourcePath,
                    this._configuration.SearchPattern);
                foreach (var f in files) {
                    await this.ProcessAsync(f, this.GetOutputPath(f))
                        .ConfigureAwait(false);
                }

            } else {
                await this.ProcessAsync(this._configuration.SourcePath,
                    this.GetOutputPath(this._configuration.SourcePath))
                    .ConfigureAwait(false);
            }
        }

        #region Private methods
        /// <summary>
        /// Generates the output path for the given input path.
        /// </summary>
        /// <param name="inputPath"></param>
        /// <returns></returns>
        private string GetOutputPath(string inputPath) {
            return this._configuration.Inline
                ? Path.GetTempFileName()
                : inputPath + this._configuration.DestinationSuffix;
        }

        /// <summary>
        /// Process the content of <paramref name="reader"/> line-by-line and
        /// write the result to <paramref name="writer"/>.
        /// </summary>
        /// <param name="reader"></param>
        /// <param name="writer"></param>
        private void ProcessLines(StreamReader reader, StreamWriter writer) {
            Debug.Assert(reader != null);
            Debug.Assert(writer != null);

            var line = reader.ReadLine();
            while (line != null) {
                var record = JsonConvert.DeserializeObject<JObject>(line);
                this.ProcessRecord(record);

                line = JsonConvert.SerializeObject(record);
                writer.WriteLine(line);

                line = reader.ReadLine();
            }
        }

        /// <summary>
        /// Pseudonymise all configured fields in <paramref name="token"/>.
        /// </summary>
        /// <param name="token"></param>
        private void ProcessRecord(JObject token) {
            foreach (var p in this._configuration.EraseFields) {
                var tokens = token.SelectTokens(p);
                foreach (var t in tokens) {
                    t.Parent.Remove();
                }
            }

            foreach (var p in this._configuration.IPAddressFields) {
                var tokens = token.SelectTokens(p);
                foreach (JValue t in tokens) {
                    var ip = IPAddress.Parse((string) t.Value);
                    ip = this._anonymiser.Anonymise(ip);
                    t.Replace(ip.ToString());
                }
            }

            foreach (var p in this._configuration.MacAddressFields) {
                var tokens = token.SelectTokens(p);
                foreach (JValue t in tokens) {
                    var mac = PhysicalAddress.Parse((string) t.Value);
                    var bytes = mac.GetAddressBytes();
                    bytes = this._anonymiser.Anonymise(bytes);
                    mac = new PhysicalAddress(bytes);
                    t.Replace(mac.ToString());
                }
            }

            {
                var c = this._configuration.CommandLineFields
                    ?? new Configuration.StringPseudonymisation();

                foreach (var p in c.Paths) {
                    var tokens = token.SelectTokens(p);
                    foreach (JValue t in tokens) {
                        var value = (string) t.Value;
                        value = this._stringScrambler.ScrambleCommandLine(
                            value, c.Alphabet, c.Scaling);
                        t.Replace(value);
                    }
                }
            }

            {
                var c = this._configuration.DomainNameFields
                    ?? new Configuration.StringPseudonymisation();

                foreach (var p in c.Paths) {
                    var tokens = token.SelectTokens(p);
                    foreach (JValue t in tokens) {
                        var value = (string) t.Value;
                        value = this._stringScrambler.ScrambleDomainName(
                            value, c.Alphabet, c.Scaling);
                        t.Replace(value);
                    }
                }
            }

            {
                var c = this._configuration.PathFields
                    ?? new Configuration.StringPseudonymisation();

                foreach (var p in c.Paths) {
                    var tokens = token.SelectTokens(p);
                    foreach (JValue t in tokens) {
                        var value = (string) t.Value;
                        value = this._stringScrambler.ScramblePath(
                            value, c.Alphabet, c.Scaling);
                        t.Replace(value);
                    }
                }
            }

            {
                var c = this._configuration.ScaledStringFields
                    ?? new Configuration.StringPseudonymisation();

                foreach (var p in c.Paths) {
                    var tokens = token.SelectTokens(p);
                    foreach (JValue t in tokens) {
                        var value = (string) t.Value;
                        value = this._stringScrambler.Scramble(
                            value, c.Alphabet, c.Scaling);
                        t.Replace(value);
                    }
                }
            }

            {
                var c = this._configuration.FixedLengthStringFields
                    ?? new Configuration.StringPseudonymisation();

                foreach (var p in c.Paths) {
                    var tokens = token.SelectTokens(p);
                    foreach (JValue t in tokens) {
                        var value = (string) t.Value;
                        value = this._stringScrambler.Scramble(
                            value, c.Alphabet, 1.0f);
                        t.Replace(value);
                    }
                }
            }
        }

        /// <summary>
        /// If an output writer is configured, write the given string.
        /// </summary>
        /// <param name="output"></param>
        private void WriteOutput(string output) {
            if (this._writer != null) {
                this._writer.WriteLine(output);
            }
        }

        /// <summary>
        /// If an output writer is configured, format and write the given
        /// string.
        /// </summary>
        /// <param name="format"></param>
        /// <param name="args"></param>
        private void WriteOutput(string format, params object[] args) {
            var msg = string.Format(CultureInfo.CurrentCulture, format, args);
            this.WriteOutput(msg);
        }
        #endregion

        #region Private fields
        /// <summary>
        /// The Crypto-PAn implementation.
        /// </summary>
        private readonly Anonymiser _anonymiser;

        /// <summary>
        /// The configuration pointing towards the fields to be transformed.
        /// </summary>
        private readonly Configuration _configuration;

        /// <summary>
        /// The utility to pseudonymise strings.
        /// </summary>
        private readonly StringScrambler _stringScrambler;

        /// <summary>
        /// An optional text writer for progress messages.
        /// </summary>
        private readonly TextWriter _writer;
        #endregion
    }
}
