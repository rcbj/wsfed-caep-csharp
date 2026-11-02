// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

namespace IyaSec.WsFed;

public sealed class MemoryReplayCache
{
    readonly object _gate = new();
    readonly Dictionary<string, long> _entries = new();
    readonly int _max;

    public MemoryReplayCache(int maxEntries = 0)
    {
        _max = maxEntries <= 0 ? 10000 : maxEntries;
    }

    public bool CheckAndRecord(string assertionId, DateTimeOffset expiresAt)
    {
        lock (_gate)
        {
            var now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            if (_entries.TryGetValue(assertionId, out var until) && until > now) return true;
            if (_entries.Count >= _max)
            {
                foreach (var key in _entries.Where(pair => pair.Value <= now).Select(pair => pair.Key).ToList())
                    _entries.Remove(key);
                if (_entries.Count >= _max)
                    throw new WsFedException("replay", "the replay cache holds " + _max + " live assertions and cannot record another");
            }
            _entries[assertionId] = expiresAt.ToUnixTimeMilliseconds();
            return false;
        }
    }
}
