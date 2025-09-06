// SPDX-License-Identifier: MIT
//
// AlyanaGlobal Device Guard
//
// The PolicyClient fetches the current allow‑list from the backend and
// determines whether a given domain should be permitted.  It stores
// domain patterns in memory and implements simple wildcard matching for
// suffix patterns (e.g. "*.google.com").  In Phase 1 the base URL
// and device token are set via properties after installation.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text.Json;
using System.Threading.Tasks;

namespace AlyanaGlobal.DeviceGuard
{
    public class PolicyClient
    {
        private readonly Logger _logger;
        private readonly HttpClient _http;
        private HashSet<string> _allow;

        /// <summary>
        /// Base URL of the backend API.  Should end with "/api/v1".
        /// </summary>
        public string BaseUrl { get; set; } = "https://console.alyanaglobal.com/api/v1";

        /// <summary>
        /// Bearer token assigned during enrolment.
        /// </summary>
        public string DeviceToken { get; set; }

        public PolicyClient(Logger logger)
        {
            _logger = logger;
            _http = new HttpClient();
            _allow = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        }

        /// <summary>
        /// Refresh the allow‑list by calling the backend.  If the device
        /// has not yet been activated the backend will return a pending
        /// response and the allow‑list will remain unchanged.
        /// </summary>
        public async Task RefreshAsync()
        {
            if (string.IsNullOrEmpty(DeviceToken))
            {
                return;
            }
            try
            {
                var req = new HttpRequestMessage(HttpMethod.Get, BaseUrl + "/policy");
                req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", DeviceToken);
                var resp = await _http.SendAsync(req);
                if (!resp.IsSuccessStatusCode)
                {
                    return;
                }
                var json = await resp.Content.ReadAsStringAsync();
                using var doc = JsonDocument.Parse(json);
                if (doc.RootElement.TryGetProperty("domains", out var domainsElem) && domainsElem.ValueKind == JsonValueKind.Array)
                {
                    var newSet = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                    foreach (var item in domainsElem.EnumerateArray())
                    {
                        if (item.ValueKind == JsonValueKind.String)
                        {
                            var val = item.GetString();
                            if (!string.IsNullOrEmpty(val))
                            {
                                newSet.Add(val);
                            }
                        }
                    }
                    _allow = newSet;
                }
            }
            catch
            {
                // Swallow exceptions during refresh; the old policy remains in effect
            }
        }

        /// <summary>
        /// Return true if <paramref name="domain"/> matches any of the
        /// configured allow‑list patterns.  Suffix wildcards (e.g.
        /// "*.example.com") are supported.
        /// </summary>
        public bool IsAllowed(string domain)
        {
            if (string.IsNullOrEmpty(domain))
            {
                return false;
            }
            // Normalise domain to lower case and strip trailing dot
            domain = domain.Trim().TrimEnd('.').ToLowerInvariant();
            foreach (var pattern in _allow)
            {
                if (string.IsNullOrEmpty(pattern))
                    continue;
                if (!pattern.StartsWith("*"))
                {
                    // Exact match
                    if (string.Equals(domain, pattern, StringComparison.OrdinalIgnoreCase))
                    {
                        return true;
                    }
                }
                else
                {
                    // Suffix wildcard: remove leading '*' and compare end of domain
                    var suffix = pattern.Substring(1);
                    if (domain.EndsWith(suffix, StringComparison.OrdinalIgnoreCase))
                    {
                        return true;
                    }
                }
            }
            return false;
        }
    }
}