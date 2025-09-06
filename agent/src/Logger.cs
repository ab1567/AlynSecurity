// SPDX-License-Identifier: MIT
//
// AlyanaGlobal Device Guard
//
// The Logger collects blocked domain events and posts them to the backend
// in batches.  Phase 1 defines the public methods but does not yet
// implement HTTP submission; events are simply queued.  A future phase
// will flush the queue based on a timer or batch size.

using System;
using System.Collections.Concurrent;
using System.Threading.Tasks;

namespace AlyanaGlobal.DeviceGuard
{
    public class Logger
    {
        private readonly ConcurrentQueue<LogEvent> _queue = new ConcurrentQueue<LogEvent>();

        /// <summary>
        /// Enqueue a blocked domain attempt.  The caller should provide
        /// the domain, the user context, the process name (if known)
        /// and the source IP address on the device.
        /// </summary>
        public void QueueBlocked(string domain, string user, string process, string ip)
        {
            var evt = new LogEvent
            {
                Timestamp = DateTime.UtcNow,
                Domain = domain,
                Verdict = "blocked",
                User = user,
                Process = process,
                SourceIp = ip,
            };
            _queue.Enqueue(evt);
            // In Phase 1 we do not automatically flush; a future timer will
            // call FlushAsync() when appropriate.
        }

        /// <summary>
        /// Flush the queued events to the backend.  Not implemented in
        /// Phase 1.
        /// </summary>
        public async Task FlushAsync()
        {
            // TODO: implement HTTP POST to the backend /logs endpoint.
            await Task.CompletedTask;
        }
    }

    public class LogEvent
    {
        public DateTime Timestamp { get; set; }
        public string Domain { get; set; }
        public string Verdict { get; set; }
        public string User { get; set; }
        public string Process { get; set; }
        public string SourceIp { get; set; }
    }
}