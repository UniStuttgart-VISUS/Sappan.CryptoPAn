// <copyright file="Options.cs" company="Universität Stuttgart">
// Copyright © 2021 SAPPAN Consortium. All rights reserved.
// </copyright>
// <author>Christoph Müller</author>

using CommandLine;


namespace Sappan.JsonSanitiser {

    /// <summary>
    /// Container for the command line arguments.
    /// </summary>
    public sealed class Options {

        /// <summary>
        /// Gets or sets the path to the configuration file.
        /// </summary>
        [Option('c',
            "configuration",
            Required = true,
            HelpText = "Specifies the file configuring the pseudonymisation.")]
        public string Configuration { get; set; }

        /// <summary>
        /// Gets or sets whether data come from standard input.
        /// </summary>
        [Option('i',
            "standard-input",
            Required = false,
            Default = false,
            HelpText = "Reads the input from standard input instead from the configured path.")]
        public bool IsStandardInput { get; set; }

        /// <summary>
        /// Gets or sets whether the system should write progress reports on the
        /// console.
        /// </summary>
        [Option('v',
            "verbose",
            Default = false,
            Required = false,
            HelpText = "Enable progress output on the console.")]
        public bool IsVerbose { get; set; }
    }
}
