// <copyright file="StringExtensions.cs" company="Universität Stuttgart">
// Copyright © 2020 SAPPAN Consortium. All rights reserved.
// </copyright>
// <author>Christoph Müller</author>

using System;
using System.Collections.Generic;


namespace Sappan.JsonSanitiser {

    /// <summary>
    /// Extension methods for <see cref="string" />.
    /// </summary>
    public static class StringExtensions {

        /// <summary>
        /// Splits a string at characters that fulful the given
        /// <paramref name="predicate"/>.
        /// </summary>
        /// <remarks>
        /// Inspired by the answer to
        /// https://stackoverflow.com/questions/298830/split-string-containing-command-line-parameters-into-string-in-c-sharp
        /// </remarks>
        /// <param name="that"></param>
        /// <returns></returns>
        public static IEnumerable<string> SplitIf(this string that,
                Func<char, bool> predicate) {
            _ = predicate ?? throw new ArgumentNullException(nameof(predicate));

            if (that == null) {
                yield break;
            }

            int start = 0;

            for (int i = 0; i < that.Length; ++i) {
                if (predicate(that[i])) {
                    yield return that.Substring(start, i - start);
                    start = i + 1;
                }
            }

            yield return that.Substring(start);
        }
    }
}
