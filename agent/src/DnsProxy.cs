// SPDX-License-Identifier: MIT
//
// AlyanaGlobal Device Guard
//
// This is a minimal skeleton for the DNS proxy used by the Device Guard
// agent.  It listens on localhost and forwards allowed queries to an
// upstream resolver.  Domains not on the allow‑list return an NXDOMAIN
// response and are recorded via the Logger.  Phase 1 provides only
// structural placeholders; the actual DNS parsing and forwarding logic
// will be implemented in later phases.

using System;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace AlyanaGlobal.DeviceGuard
{
    public class DnsProxy
    {
        private readonly PolicyClient _policyClient;
        private readonly Logger _logger;
        private UdpClient _udpClient;
        private CancellationTokenSource _cts;

        public DnsProxy(PolicyClient policyClient, Logger logger)
        {
            _policyClient = policyClient;
            _logger = logger;
        }

        /// <summary>
        /// Start listening for DNS queries on 127.0.0.1:53.  This method
        /// spawns a background task to receive packets.  It is safe to
        /// call Start multiple times; subsequent calls will have no effect.
        /// </summary>
        public void Start()
        {
            if (_udpClient != null)
            {
                return;
            }
            _cts = new CancellationTokenSource();
            _udpClient = new UdpClient(new IPEndPoint(IPAddress.Loopback, 53));
            Task.Run(() => ReceiveLoopAsync(_cts.Token));
        }

        /// <summary>
        /// Stop listening for DNS queries and close the underlying socket.
        /// </summary>
        public void Stop()
        {
            try
            {
                _cts?.Cancel();
                _udpClient?.Dispose();
            }
            catch
            {
                // Swallow exceptions on shutdown
            }
            finally
            {
                _udpClient = null;
                _cts = null;
            }
        }

        private async Task ReceiveLoopAsync(CancellationToken token)
        {
            while (!token.IsCancellationRequested)
            {
                try
                {
                    var result = await _udpClient.ReceiveAsync();
                    // In Phase 1 we do not implement full DNS parsing.
                    // Instead, simply drop all packets.  You can use
                    // existing DNS libraries (e.g. ARSoft.Tools.Net) in
                    // future phases to decode queries and forward them.
                    // Example placeholder:
                    // string domain = ExtractDomainFromQuery(result.Buffer);
                    // if (_policyClient.IsAllowed(domain)) { ForwardUpstream(...) }
                    // else { _logger.QueueBlocked(domain, Environment.UserName, "", result.RemoteEndPoint.Address.ToString()); RespondNXDomain() }
                }
                catch (ObjectDisposedException)
                {
                    break;
                }
                catch (Exception)
                {
                    // Ignore errors; continue listening
                }
            }
        }
    }
}