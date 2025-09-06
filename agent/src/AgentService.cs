// SPDX-License-Identifier: MIT
//
// AlyanaGlobal Device Guard
//
// This file defines the Windows Service entry point for the Device Guard
// agent.  It wires together the DNS proxy, policy client, logging and
// network hardening components.  The implementation in Phase 1 is
// intentionally minimal; real DNS parsing, error handling and policy
// enforcement will be added in subsequent phases.

using System;
using System.ServiceProcess;
using System.Threading;
using System.Threading.Tasks;

namespace AlyanaGlobal.DeviceGuard
{
    public class AgentService : ServiceBase
    {
        private DnsProxy _dns;
        private PolicyClient _policy;
        private Logger _logger;
        private Timer _policyTimer;
        private Timer _dnsWatchdog;

        protected override void OnStart(string[] args)
        {
            _logger = new Logger();
            _policy = new PolicyClient(_logger);
            _dns = new DnsProxy(_policy, _logger);
            _dns.Start();
            // Apply local DNS and firewall hardening immediately on startup.
            NetworkHardener.ApplyLocalhostDNS();
            NetworkHardener.EnsureFirewallRules();
            // Schedule periodic policy refresh.
            _policyTimer = new Timer(async _ => await _policy.RefreshAsync(), null,
                dueTime: TimeSpan.Zero, period: TimeSpan.FromMinutes(5));
            // Schedule periodic DNS enforcement to prevent tampering.
            _dnsWatchdog = new Timer(_ => NetworkHardener.ApplyLocalhostDNS(), null,
                dueTime: TimeSpan.FromMinutes(1), period: TimeSpan.FromMinutes(5));
        }

        protected override void OnStop()
        {
            _dns.Stop();
            _policyTimer?.Dispose();
            _dnsWatchdog?.Dispose();
        }

        public static void Main(string[] args)
        {
            ServiceBase.Run(new AgentService());
        }
    }
}