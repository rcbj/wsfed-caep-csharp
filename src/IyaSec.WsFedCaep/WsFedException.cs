// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

namespace IyaSec.WsFed;

public sealed class WsFedException : Exception
{
    public string Code { get; }

    public WsFedException(string code, string message, Exception? cause = null) : base(message, cause)
    {
        Code = code;
    }
}
