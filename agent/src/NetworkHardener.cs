// SPDX-License-Identifier: MIT
//
// AlyanaGlobal Device Guard
//
// The NetworkHardener contains helper methods to configure the device
// network stack for the DNS proxy.  In Phase 1 these methods are
// placeholders; they will be expanded in later phases to set the
// system DNS servers to 127.0.0.1 and to add firewall rules that
// prevent traffic to external DNS resolvers.

using System;

namespace AlyanaGlobal.DeviceGuard
{
    public static class NetworkHardener
    {
        /// <summary>
        /// Force all network adapters to use the local DNS proxy.  In
        /// Phase 1 this method logs the intended action only; you can
        /// implement netsh or WMI calls in a future phase.
        /// </summary>
        public static void ApplyLocalhostDNS()
        {
            // TODO: call netsh or use System.Management to set DNS
            // server addresses to 127.0.0.1.  For now, emit a debug log.
            Console.WriteLine("[NetworkHardener] Would set DNS to 127.0.0.1");
        }

        /// <summary>
        /// Ensure firewall rules exist to block outbound DNS traffic
        /// except to localhost.  In Phase 1 this method logs the
        /// intended action only.
        /// </summary>
        public static void EnsureFirewallRules()
        {
            // TODO: call netsh advfirewall to block UDP/TCP 53/853
            // except when the destination is 127.0.0.1.  For now, emit a debug log.
            Console.WriteLine("[NetworkHardener] Would add firewall rules to block external DNS");
        }
    }
}