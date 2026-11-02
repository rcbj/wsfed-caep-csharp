// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

using System.Diagnostics;
using Xunit;

namespace IyaSec.WsFed.Tests;

public class ConfigureTests
{
    static string RepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir != null)
        {
            if (File.Exists(Path.Combine(dir.FullName, "scripts", "configure_iya_sts.py")))
                return dir.FullName;
            dir = dir.Parent;
        }
        throw new InvalidOperationException("configure_iya_sts.py was not found");
    }

    [Fact]
    public void SignalsBehavior()
    {
        var root = RepoRoot();
        var script = Path.Combine(root, "scripts", "configure_iya_sts.py");
        Assert.True(File.Exists(script));
        var dir = Directory.CreateTempSubdirectory("wsfed-configure-");
        try
        {
            var baseJson = """
{
  "realm": "http://localhost:3000/",
  "replyUrl": "http://localhost:3000/wsfed",
  "privateKey": "generated/rp.key",
  "certificate": "generated/rp.crt",
  "idpMetadata": "generated/idp-metadata.xml",
  "idpCa": "generated/idp-ca.pem"
}
""";
            string Write(string name, string body)
            {
                var path = Path.Combine(dir.FullName, name);
                File.WriteAllText(path, body);
                return path;
            }
            var config = Write("wsfed.json", baseJson);
            var withSsf = Write("wsfed-ssf.json", baseJson.Replace("\n}", ",\n  \"ssf\": {\"transmitter\": \"https://localhost:8081\"}\n}", StringComparison.Ordinal));
            var off = Write("off.json", baseJson.Replace("\n}", ",\n  \"signals\": false,\n  \"ssf\": {\"transmitter\": \"https://localhost:8081\"}\n}", StringComparison.Ordinal));
            var on = Write("on.json", baseJson.Replace("\n}", ",\n  \"signals\": true,\n  \"ssf\": {\"transmitter\": \"https://localhost:8081\"}\n}", StringComparison.Ordinal));
            var bad = Write("bad.json", baseJson.Replace("\n}", ",\n  \"signals\": \"no\"\n}", StringComparison.Ordinal));
            var code = """
import json, sys
sys.path.insert(0, sys.argv[1])
from configure_iya_sts import files_of, plan_for
base, with_ssf, off, on, bad = sys.argv[2:]
files = files_of(base)
ssf = files_of(with_ssf)
assert any(call["path"].endswith("/applications/add-certificate") for call in plan_for(ssf, "https://localhost:8081", ""))
assert not any(call["path"].endswith("/applications/add-certificate") for call in plan_for(files, "https://localhost:8081", ""))
off_files = files_of(off)
assert off_files["signals"] is False
assert off_files["ssf_transmitter"] == "https://localhost:8081"
assert off_files["realm"] == "http://localhost:3000/"
assert off_files["reply_url"] == "http://localhost:3000/wsfed"
assert not any(call["path"].endswith("/applications/add-certificate") for call in plan_for(off_files, "https://localhost:8081", ""))
assert not any(call["path"].endswith("/roles/add-member") for call in plan_for(off_files, "https://localhost:8081", ""))
assert "signals" not in files_of(on)
assert any(call["path"].endswith("/applications/add-certificate") for call in plan_for(files_of(on), "https://localhost:8081", ""))
try:
    files_of(bad)
except ValueError as err:
    assert str(err) == "signals must be true or false", str(err)
else:
    raise SystemExit("signals string was accepted")
print("ok")
""";
            var psi = new ProcessStartInfo
            {
                FileName = "python3",
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
            };
            psi.ArgumentList.Add("-c");
            psi.ArgumentList.Add(code);
            psi.ArgumentList.Add(Path.GetDirectoryName(script)!);
            psi.ArgumentList.Add(config);
            psi.ArgumentList.Add(withSsf);
            psi.ArgumentList.Add(off);
            psi.ArgumentList.Add(on);
            psi.ArgumentList.Add(bad);
            using var proc = Process.Start(psi);
            Assert.NotNull(proc);
            var stdout = proc.StandardOutput.ReadToEnd();
            var stderr = proc.StandardError.ReadToEnd();
            proc.WaitForExit();
            Assert.True(proc.ExitCode == 0, stdout + stderr);
            Assert.Contains("ok", stdout);
        }
        finally { dir.Delete(true); }
    }
}
