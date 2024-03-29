﻿// <copyright file="JsonProcessor.cs" company="Universität Stuttgart">
// Copyright © 2020 SAPPAN Consortium. All rights reserved.
// </copyright>
// <author>Christoph Müller</author>

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Sappan.CryptoPAn;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.IO.Compression;
using System.Net;
using System.Net.NetworkInformation;
using System.Threading;
using System.Threading.Tasks;


namespace Sappan.JsonSanitiser {

    /// <summary>
    /// Implements the processing of the JSON data of a single file.
    /// </summary>
    internal sealed class JsonProcessor {

        #region Public constructor
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
        #endregion

        #region Public method
        /// <summary>
        /// Process the JSON file at <paramref name="inputPath"/> and store the
        /// anonymised version to <paramref name="outputPath"/>.
        /// </summary>
        /// <param name="inputPath">The path to the input file.</param>
        /// <param name="outputPath">The path to the output file.</param>
        /// <param name="isRecordLines">If <c>true</c>, assume that the file
        /// contains on JSON record per line. If <c>false</c>, probe the content
        /// of the file for holding a JSON array or a record per line.</param>
        public void Process(string inputPath, string outputPath,
                bool isRecordLines = false) {
            this.WriteOutput(Properties.Resources.MsgProcessingFile,
                inputPath, outputPath);

            using (var f = File.Open(inputPath, FileMode.Open,
                        FileAccess.Read, FileShare.Read)) {
                if (inputPath.IsGzip()) {
                    try {
                        using (var z = new GZipStream(f, CompressionMode.Decompress)) {
                            this.ProcessStream(z, isRecordLines, inputPath, outputPath);
                        }
                    } catch (NotSupportedException) {
                        // Unfortunately, the GZip stream cannot seek if we need
                        // to start all over in case the content of the file is
                        // not a JSON array, so we need to start over and force
                        // line-by-line processing.
                        this.Process(inputPath, outputPath, true);
                    }

                } else {
                    this.ProcessStream(f, isRecordLines, inputPath, outputPath);
                }
            }
        }

        /// <summary>
        /// Process the JSON file at <paramref name="inputPath"/> and store the
        /// anonymised version to <paramref name="outputPath"/>.
        /// </summary>
        /// <param name="inputPath">The path to the input file.</param>
        /// <param name="outputPath">The path to the output file.</param>
        /// <param name="isRecordLines">If <c>true</c>, assume that the file
        /// contains on JSON record per line. If <c>false</c>, probe the content
        /// of the file for holding a JSON array or a record per line.</param>
        /// <returns>A task to wait for completion of the work.</returns>
        public Task ProcessAsync(string inputPath, string outputPath,
                bool isRecordLines = false) {
            return Task.Factory.StartNew(() => {
                this.Process(inputPath, outputPath, isRecordLines);
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

                var stack = new Stack<string>();
                stack.Push(this._configuration.SourcePath);

                while (stack.Count > 0) {
                    var dir = stack.Pop();
                    var files = Directory.GetFiles(dir,
                        this._configuration.SearchPattern);
                    foreach (var f in files) {
                        await this.ProcessAsync(f, this.GetOutputPath(f),
                            this._configuration.LineByLine)
                            .ConfigureAwait(false);
                    }

                    if (this._configuration.Recurse) {
                        var dirs = Directory.GetDirectories(dir);
                        foreach (var d in dirs) {
                            stack.Push(d);
                        }
                    }
                }

            } else {
                await this.ProcessAsync(this._configuration.SourcePath,
                    this.GetOutputPath(this._configuration.SourcePath),
                    this._configuration.LineByLine)
                    .ConfigureAwait(false);
            }
        }

        /// <summary>
        /// Processes a single, JSON-encoded record.
        /// </summary>
        /// <param name="json"></param>
        /// <returns></returns>
        public string ProcessRecord(string json) {
            var obj = JObject.Parse(json);
            this.ProcessRecord(obj);
            return obj.ToString();
        }
        #endregion

        #region Private class methods
        /// <summary>
        /// Process the configured fields in <paramref name="token"/> using the
        /// given <paramref name="processor"/>.
        /// </summary>
        /// <param name="token"></param>
        /// <param name="paths"></param>
        /// <param name="processor"></param>
        private static void ProcessFields(JObject token,
                IEnumerable<string> paths,
                Func<string, string> processor) {
            Debug.Assert(token != null);
            Debug.Assert(processor != null);

            if (paths != null) {
                foreach (var p in paths) {
                    var tokens = token.SelectTokens(p);
                    foreach (var t in tokens) {
                        if (t is JArray array) {
                            // Process elements of array-valued fields.
                            for (int i = 0; i < array.Count; ++i) {
                                var value = array[i].Value<string>();
                                value = processor(value);
                                array[i].Replace(value);
                            }

                        } else {
                            // Assume 't' is a scalar value.
                            var value = t.Value<string>();
                            value = processor(value);
                            t.Replace(value);
                        }
                    }
                } /* foreach (var p in paths) */
            } /* end if (paths != null) */
            }
        #endregion

        #region Private methods
        /// <summary>
        /// Generates the output path for the given input path.
        /// </summary>
        /// <param name="inputPath"></param>
        /// <returns></returns>
        private string GetOutputPath(string inputPath) {
            Debug.Assert(inputPath != null);
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

            ProcessFields(token, this._configuration.IPAddressFields, (v) => {
                var ip = IPAddress.Parse(v);
                ip = this._anonymiser.Anonymise(ip);
                return ip.ToString();
            });

            ProcessFields(token, this._configuration.MacAddressFields, (v) => {
                var mac = PhysicalAddress.Parse(v);
                var bytes = mac.GetAddressBytes();
                bytes = this._anonymiser.Anonymise(bytes);
                mac = new PhysicalAddress(bytes);
                return mac.ToString();
            });

            {
                var c = this._configuration.CommandLineFields;
                ProcessFields(token, c.Paths, (v) => this._stringScrambler
                    .ScrambleCommandLine(v, c.Alphabet, c.Scaling));
            }

            {
                var c = this._configuration.DomainNameFields;
                ProcessFields(token, c.Paths, (v) => this._stringScrambler
                    .ScrambleDomainName(v, c.Alphabet, c.Scaling));
            }

            {
                var c = this._configuration.PathFields;
                ProcessFields(token, c.Paths, (v) => this._stringScrambler
                    .ScramblePath(v, c.Alphabet, c.Scaling));
            }

            {
                var c = this._configuration.ScaledStringFields;
                ProcessFields(token, c.Paths, (v) => this._stringScrambler
                    .Scramble(v, c.Alphabet, c.Scaling));
            }

            {
                var c = this._configuration.FixedLengthStringFields;
                ProcessFields(token, c.Paths, (v) => this._stringScrambler
                    .Scramble(v, c.Alphabet, 1.0f));
            }
        }

        /// <summary>
        /// Process the JSON stream <paramref name="inputStream"/> and store
        /// the sanitised version to <paramref name="outputPath"/>.
        /// </summary>
        /// <param name="inputStream">The stream to read from.</param>
        /// <param name="isRecordLines">Forces the processing of the file
        /// line-by-line. If <c>false</c>, the file is probed.</param>
        /// <param name="inputPath">The path of <paramref name="inputStream"/>,
        /// which is used to overwrite the original file if inline processing
        /// was specified.</param>
        /// <param name="outputPath">The path of the output file.</param>
        private void ProcessStream(Stream inputStream, bool isRecordLines,
                string inputPath, string outputPath) {
            Debug.Assert(inputStream != null);
            Debug.Assert(inputPath != null);
            Debug.Assert(outputPath != null);

            using (var sr = new StreamReader(inputStream))
            using (var jr = new JsonTextReader(sr))
            using (var fw = File.Open(outputPath, FileMode.Create,
                FileAccess.Write, FileShare.Read))
            using (var sw = new StreamWriter(fw))
            using (var jw = new JsonTextWriter(sw)) {
                if (isRecordLines) {
                    // User forced one-record-by-line style.
                    this.ProcessLines(sr, sw);

                } else {
                    // Check the content of the file and process it accordinly.
                    var serialiser = new JsonSerializer();

                    // Read the stuff and decide based on the token returned
                    // whether the file contains a valid JSON array or must be
                    // processed line-by-line.
                    var data = serialiser.Deserialize<JToken>(jr);

                    if (data is JArray array) {
                        // Pseudonymise each element in the array and write it
                        // back as an array.
                        this.WriteOutput(Properties.Resources.MsgProcessArray,
                            inputPath);
                        foreach (JObject record in array) {
                            this.ProcessRecord(record);
                        }
                        serialiser.Serialize(jw, data);

                    } else {
                        // This must be processed line-by-line, so reset the
                        // stream and retry. Note it is important to discard any
                        // buffered data in the stream reader, because this
                        // would be processed again by ProcessLines().
                        this.WriteOutput(
                            Properties.Resources.MsgProcessLineByLine,
                            inputPath);
                        inputStream.Seek(0, SeekOrigin.Begin);
                        sr.DiscardBufferedData();
                        this.ProcessLines(sr, sw);
                    } /* end if (data is JArray array) */
                } /* end if (isRecordLines) */
            }

            if (this._configuration.Inline) {
                this.WriteOutput(Properties.Resources.MsgReplaceSource,
                    inputPath);
                File.Delete(inputPath);
                File.Move(outputPath, inputPath);
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
