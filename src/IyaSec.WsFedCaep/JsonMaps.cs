// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

using System.Text;
using System.Text.Json;

namespace IyaSec.WsFed;

public static class JsonMaps
{
    public static Dictionary<string, object?> ParseObject(byte[] json) => Parse(Encoding.UTF8.GetString(json));

    public static Dictionary<string, object?> Parse(string json)
    {
        using var doc = JsonDocument.Parse(json);
        if (doc.RootElement.ValueKind != JsonValueKind.Object)
            throw new WsFedException("config", "the configuration must be an object");
        return (Dictionary<string, object?>)FromElement(doc.RootElement)!;
    }

    public static object? FromElement(JsonElement el) => el.ValueKind switch
    {
        JsonValueKind.String => el.GetString(),
        JsonValueKind.True => true,
        JsonValueKind.False => false,
        JsonValueKind.Null => null,
        JsonValueKind.Number => Number(el),
        JsonValueKind.Object => Object(el),
        JsonValueKind.Array => Array(el),
        _ => null,
    };

    static object Number(JsonElement el)
    {
        var raw = el.GetRawText();
        if (raw.Contains('.') || raw.Contains('e') || raw.Contains('E'))
            return el.GetDouble();
        if (long.TryParse(raw, out var whole)) return whole;
        return el.GetDouble();
    }

    static Dictionary<string, object?> Object(JsonElement el)
    {
        var map = new Dictionary<string, object?>(StringComparer.Ordinal);
        foreach (var prop in el.EnumerateObject()) map[prop.Name] = FromElement(prop.Value);
        return map;
    }

    static List<object?> Array(JsonElement el)
    {
        var list = new List<object?>();
        foreach (var item in el.EnumerateArray()) list.Add(FromElement(item));
        return list;
    }
}
