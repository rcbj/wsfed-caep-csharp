// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

using System.Text.Json;

namespace IyaSec.WsFed;

public static class Cli
{
    public const string Usage = """
Usage:
  wsfed-caep generate-keys --config <wsfed.json> [--cn <name>] [--days <n>] [--bits <n>] [--force]
  wsfed-caep generate-keys --key <file> --cert <file> [--cn <name>] [--days <n>] [--bits <n>] [--force]
      A new RSA key and a self-signed certificate, written where the configuration's privateKey and
      certificate point (or to --key and --cert). Refuses to replace existing files without --force.
      The key decrypts encrypted assertions and can authenticate the Shared Signals receiver (mutual
      TLS); WS-Federation itself signs nothing. The common name defaults to one naming the realm.

  wsfed-caep metadata --config <wsfed.json> [--out <file>]
      This relying party's federation metadata, from the configuration (and its certificate, when it
      has one): give it to the identity provider. Written to --out, or to standard output.
""";

    public static int Main(string[] argv, TextWriter? output = null)
    {
        output ??= Console.Out;
        string command;
        Dictionary<string, string> args;
        try { (command, args) = Parse(argv); }
        catch (Exception ex)
        {
            Console.Error.WriteLine(ex.Message);
            return 1;
        }
        if (command == "" || args.ContainsKey("help") || command == "help")
        {
            output.WriteLine(Usage);
            return 0;
        }
        if (command == "generate-keys")
        {
            string key;
            string cert;
            string commonName;
            try { (key, cert, commonName) = KeyPaths(args); }
            catch (Exception ex)
            {
                Console.Error.WriteLine(ex.Message);
                return 1;
            }
            if (!args.ContainsKey("force") && (File.Exists(key) || File.Exists(cert)))
            {
                var which = File.Exists(key) ? key : cert;
                Console.Error.WriteLine(which + " already exists; pass --force to replace the key pair.");
                Console.Error.WriteLine("Replacing it means giving the identity provider the new metadata before it next encrypts to this relying party.");
                return 1;
            }
            var days = 1095;
            var bits = 3072;
            if (args.TryGetValue("days", out var daysText))
            {
                if (!int.TryParse(daysText, out days) || days <= 0)
                {
                    Console.Error.WriteLine("--days must be a positive whole number");
                    return 1;
                }
            }
            if (args.TryGetValue("bits", out var bitsText))
            {
                if (!int.TryParse(bitsText, out bits) || bits is not (2048 or 3072 or 4096))
                {
                    Console.Error.WriteLine("--bits must be 2048, 3072 or 4096");
                    return 1;
                }
            }
            KeyPair pair;
            try { pair = X509Keys.CreateSelfSigned(commonName, days, bits); }
            catch (Exception ex)
            {
                Console.Error.WriteLine(ex.Message);
                return 1;
            }
            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(key))!);
                Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(cert))!);
                File.WriteAllText(key, pair.PrivateKeyPem);
                File.WriteAllText(cert, pair.CertificatePem);
                if (!OperatingSystem.IsWindows())
                {
                    File.SetUnixFileMode(key, UnixFileMode.UserRead | UnixFileMode.UserWrite);
                    File.SetUnixFileMode(cert, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead | UnixFileMode.OtherRead);
                }
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine(ex.Message);
                return 1;
            }
            output.WriteLine("Wrote the private key  " + key + " (mode 600)");
            output.WriteLine("Wrote the certificate  " + cert);
            output.WriteLine("  subject   " + pair.Certificate.Subject);
            return 0;
        }
        if (command == "metadata")
        {
            if (!args.TryGetValue("config", out var configPath) || configPath == "")
            {
                Console.Error.WriteLine("metadata needs --config");
                Console.Error.WriteLine();
                Console.Error.WriteLine(Usage);
                return 1;
            }
            try
            {
                var raw = JsonMaps.Parse(File.ReadAllText(configPath));
                raw.Remove("idpCa");
                var party = RelyingParty.Create(raw, Path.GetDirectoryName(Path.GetFullPath(configPath)));
                var xml = party.MetadataXml();
                if (args.TryGetValue("out", out var target) && target != "")
                {
                    var path = Path.GetFullPath(target);
                    Directory.CreateDirectory(Path.GetDirectoryName(path)!);
                    File.WriteAllText(path, xml);
                    output.WriteLine("Wrote the relying party metadata to " + path);
                }
                else output.Write(xml);
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine(ex.Message);
                return 1;
            }
            return 0;
        }
        Console.Error.WriteLine("unknown command " + command);
        Console.Error.WriteLine();
        Console.Error.WriteLine(Usage);
        return 1;
    }

    static (string command, Dictionary<string, string> args) Parse(string[] argv)
    {
        if (argv.Length == 0) return ("", new Dictionary<string, string>());
        var command = argv[0];
        var args = new Dictionary<string, string>(StringComparer.Ordinal);
        for (var i = 1; i < argv.Length; i++)
        {
            var item = argv[i];
            if (!item.StartsWith("--", StringComparison.Ordinal))
                throw new InvalidOperationException("unexpected argument " + item + "\n\n" + Usage);
            var key = item[2..];
            if (key is "force" or "help")
            {
                args[key] = "true";
                continue;
            }
            if (i + 1 >= argv.Length || argv[i + 1].StartsWith("--", StringComparison.Ordinal))
                throw new InvalidOperationException("--" + key + " needs a value\n\n" + Usage);
            args[key] = argv[++i];
        }
        return (command, args);
    }

    static (string key, string cert, string commonName) KeyPaths(Dictionary<string, string> args)
    {
        args.TryGetValue("config", out var configPath);
        args.TryGetValue("key", out var key);
        args.TryGetValue("cert", out var cert);
        args.TryGetValue("cn", out var commonName);
        key ??= "";
        cert ??= "";
        commonName ??= "";
        if (!string.IsNullOrEmpty(configPath))
        {
            var raw = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(File.ReadAllText(configPath)) ?? new();
            var baseDir = Path.GetDirectoryName(Path.GetFullPath(configPath)) ?? "";
            string At(JsonElement value, string what)
            {
                if (value.ValueKind != JsonValueKind.String) return "";
                var text = value.GetString() ?? "";
                if (text == "" || text.Contains("-----BEGIN "))
                    throw new InvalidOperationException(configPath + "'s " + what + " must be a file path for generate-keys to write to");
                if (text.StartsWith("file:", StringComparison.Ordinal)) text = text[5..];
                return Path.IsPathRooted(text) ? text : Path.Combine(baseDir, text);
            }
            if (key == "" && raw.TryGetValue("privateKey", out var keyEl)) key = At(keyEl, "privateKey");
            if (cert == "" && raw.TryGetValue("certificate", out var certEl)) cert = At(certEl, "certificate");
            if (commonName == "" && raw.TryGetValue("realm", out var realmEl) && realmEl.ValueKind == JsonValueKind.String)
            {
                var realm = realmEl.GetString() ?? "";
                if (realm != "") commonName = Clip("wsfed-caep-nodejs relying party " + realm, 64);
            }
        }
        if (key == "" || cert == "")
            throw new InvalidOperationException("generate-keys needs --config, or --key and --cert\n\n" + Usage);
        key = Path.GetFullPath(key);
        cert = Path.GetFullPath(cert);
        if (commonName == "") commonName = "wsfed-caep-nodejs relying party";
        return (key, cert, commonName);
    }

    public static string Clip(string value, int n)
    {
        var count = 0;
        var chars = 0;
        foreach (var rune in value.EnumerateRunes())
        {
            if (count == n) break;
            chars += rune.Utf16SequenceLength;
            count++;
        }
        return value[..chars];
    }
}
