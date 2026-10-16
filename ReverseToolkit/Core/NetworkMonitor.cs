using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

namespace ReverseToolkit
{
    public class NetworkMonitor
    {
        private int monitoredProcessId;
        private bool isMonitoring;
        private Thread? monitorThread;
        private List<NetworkConnection> connections = new();
        private Dictionary<string, DnsCache> dnsCache = new();
        
        public event Action<NetworkPacket>? OnPacketCaptured;

        // Windows API для получения TCP/UDP таблиц
        [DllImport("iphlpapi.dll", SetLastError = true)]
        private static extern uint GetExtendedTcpTable(IntPtr pTcpTable, ref int dwOutBufLen, bool sort, int ipVersion, TCP_TABLE_CLASS tblClass, int reserved);

        [DllImport("iphlpapi.dll", SetLastError = true)]
        private static extern uint GetExtendedUdpTable(IntPtr pUdpTable, ref int dwOutBufLen, bool sort, int ipVersion, UDP_TABLE_CLASS tblClass, int reserved);

        private const int AF_INET = 2;    // IPv4
        private const int AF_INET6 = 23;  // IPv6

        private enum TCP_TABLE_CLASS
        {
            TCP_TABLE_BASIC_LISTENER,
            TCP_TABLE_BASIC_CONNECTIONS,
            TCP_TABLE_BASIC_ALL,
            TCP_TABLE_OWNER_PID_LISTENER,
            TCP_TABLE_OWNER_PID_CONNECTIONS,
            TCP_TABLE_OWNER_PID_ALL,
            TCP_TABLE_OWNER_MODULE_LISTENER,
            TCP_TABLE_OWNER_MODULE_CONNECTIONS,
            TCP_TABLE_OWNER_MODULE_ALL
        }

        private enum UDP_TABLE_CLASS
        {
            UDP_TABLE_BASIC,
            UDP_TABLE_OWNER_PID,
            UDP_TABLE_OWNER_MODULE
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct MIB_TCPROW_OWNER_PID
        {
            public uint state;
            public uint localAddr;
            public byte localPort1;
            public byte localPort2;
            public byte localPort3;
            public byte localPort4;
            public uint remoteAddr;
            public byte remotePort1;
            public byte remotePort2;
            public byte remotePort3;
            public byte remotePort4;
            public int owningPid;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct MIB_UDPROW_OWNER_PID
        {
            public uint localAddr;
            public byte localPort1;
            public byte localPort2;
            public byte localPort3;
            public byte localPort4;
            public int owningPid;
        }

        public void StartMonitoring(int processId, bool filterHTTP, bool filterDNS, bool captureAll)
        {
            if (isMonitoring)
                StopMonitoring();

            monitoredProcessId = processId;
            isMonitoring = true;
            connections.Clear();

            monitorThread = new Thread(() => MonitorLoop(filterHTTP, filterDNS, captureAll))
            {
                IsBackground = true
            };
            monitorThread.Start();
        }

        public void StopMonitoring()
        {
            isMonitoring = false;
            monitorThread?.Join(1000);
        }

        private void MonitorLoop(bool filterHTTP, bool filterDNS, bool captureAll)
        {
            var seenConnections = new HashSet<string>();

            while (isMonitoring)
            {
                try
                {
                    // Получаем TCP соединения
                    var tcpConnections = GetTcpConnections();
                    foreach (var conn in tcpConnections)
                    {
                        if (conn.ProcessId != monitoredProcessId)
                            continue;

                        string key = $"{conn.Protocol}:{conn.Source}:{conn.Destination}";
                        
                        if (!seenConnections.Contains(key))
                        {
                            seenConnections.Add(key);
                            connections.Add(conn);

                            // Пытаемся определить URL/hostname
                            if (filterHTTP || captureAll)
                            {
                                conn.Url = ResolveHostname(conn.Destination);
                            }

                            OnPacketCaptured?.Invoke(new NetworkPacket
                            {
                                Protocol = conn.Protocol,
                                Source = conn.Source,
                                Destination = conn.Destination,
                                Url = conn.Url,
                                Timestamp = DateTime.Now,
                                Data = Array.Empty<byte>()
                            });
                        }
                    }

                    // Получаем UDP соединения
                    var udpConnections = GetUdpConnections();
                    foreach (var conn in udpConnections)
                    {
                        if (conn.ProcessId != monitoredProcessId)
                            continue;

                        string key = $"{conn.Protocol}:{conn.Source}:{conn.Destination}";
                        
                        if (!seenConnections.Contains(key))
                        {
                            seenConnections.Add(key);
                            connections.Add(conn);

                            if (filterDNS || captureAll)
                            {
                                conn.Url = "UDP Traffic";
                            }

                            OnPacketCaptured?.Invoke(new NetworkPacket
                            {
                                Protocol = conn.Protocol,
                                Source = conn.Source,
                                Destination = conn.Destination,
                                Url = conn.Url,
                                Timestamp = DateTime.Now,
                                Data = Array.Empty<byte>()
                            });
                        }
                    }

                    Thread.Sleep(500); // Обновляем каждые 500ms
                }
                catch (Exception ex)
                {
                    Debug.WriteLine($"Network monitoring error: {ex.Message}");
                    Thread.Sleep(500);
                }
            }
        }

        private List<NetworkConnection> GetTcpConnections()
        {
            var connections = new List<NetworkConnection>();
            int bufferSize = 0;

            // Первый вызов: получить требуемый размер буфера
            uint init = GetExtendedTcpTable(IntPtr.Zero, ref bufferSize, true, AF_INET, TCP_TABLE_CLASS.TCP_TABLE_OWNER_PID_ALL, 0);
            if (bufferSize <= 0)
                return connections;

            IntPtr tcpTablePtr = IntPtr.Zero;

            try
            {
                tcpTablePtr = Marshal.AllocHGlobal(bufferSize);
                uint result = GetExtendedTcpTable(tcpTablePtr, ref bufferSize, true, AF_INET, TCP_TABLE_CLASS.TCP_TABLE_OWNER_PID_ALL, 0);
                
                if (result == 0)
                {
                    int rowCount = Marshal.ReadInt32(tcpTablePtr);
                    IntPtr rowPtr = (IntPtr)((long)tcpTablePtr + 4);

                    for (int i = 0; i < rowCount; i++)
                    {
                        var row = Marshal.PtrToStructure<MIB_TCPROW_OWNER_PID>(rowPtr);
                        
                        string localAddress = new IPAddress(row.localAddr).ToString();
                        int localPort = (row.localPort1 << 8) + row.localPort2;
                        
                        string remoteAddress = new IPAddress(row.remoteAddr).ToString();
                        int remotePort = (row.remotePort1 << 8) + row.remotePort2;

                        if (remoteAddress != "0.0.0.0" && remoteAddress != "127.0.0.1")
                        {
                            connections.Add(new NetworkConnection
                            {
                                Protocol = "TCP",
                                Source = $"{localAddress}:{localPort}",
                                Destination = $"{remoteAddress}:{remotePort}",
                                ProcessId = row.owningPid,
                                State = GetTcpState(row.state),
                                Timestamp = DateTime.Now.ToString("HH:mm:ss"),
                                Size = "N/A"
                            });
                        }

                        rowPtr = (IntPtr)((long)rowPtr + Marshal.SizeOf(typeof(MIB_TCPROW_OWNER_PID)));
                    }
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"GetTcpConnections error: {ex.Message}");
            }
            finally
            {
                if (tcpTablePtr != IntPtr.Zero)
                    Marshal.FreeHGlobal(tcpTablePtr);
            }

            return connections;
        }

        private List<NetworkConnection> GetUdpConnections()
        {
            var connections = new List<NetworkConnection>();
            int bufferSize = 0;

            uint init = GetExtendedUdpTable(IntPtr.Zero, ref bufferSize, true, AF_INET, UDP_TABLE_CLASS.UDP_TABLE_OWNER_PID, 0);
            if (bufferSize <= 0)
                return connections;

            IntPtr udpTablePtr = IntPtr.Zero;

            try
            {
                udpTablePtr = Marshal.AllocHGlobal(bufferSize);
                uint result = GetExtendedUdpTable(udpTablePtr, ref bufferSize, true, AF_INET, UDP_TABLE_CLASS.UDP_TABLE_OWNER_PID, 0);
                
                if (result == 0)
                {
                    int rowCount = Marshal.ReadInt32(udpTablePtr);
                    IntPtr rowPtr = (IntPtr)((long)udpTablePtr + 4);

                    for (int i = 0; i < rowCount; i++)
                    {
                        var row = Marshal.PtrToStructure<MIB_UDPROW_OWNER_PID>(rowPtr);
                        
                        string localAddress = new IPAddress(row.localAddr).ToString();
                        int localPort = (row.localPort1 << 8) + row.localPort2;

                        connections.Add(new NetworkConnection
                        {
                            Protocol = "UDP",
                            Source = $"{localAddress}:{localPort}",
                            Destination = "N/A",
                            ProcessId = row.owningPid,
                            State = "LISTENING",
                            Timestamp = DateTime.Now.ToString("HH:mm:ss"),
                            Size = "N/A"
                        });

                        rowPtr = (IntPtr)((long)rowPtr + Marshal.SizeOf(typeof(MIB_UDPROW_OWNER_PID)));
                    }
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"GetUdpConnections error: {ex.Message}");
            }
            finally
            {
                if (udpTablePtr != IntPtr.Zero)
                    Marshal.FreeHGlobal(udpTablePtr);
            }

            return connections;
        }

        private string GetTcpState(uint state)
        {
            return state switch
            {
                1 => "CLOSED",
                2 => "LISTENING",
                3 => "SYN_SENT",
                4 => "SYN_RCVD",
                5 => "ESTABLISHED",
                6 => "FIN_WAIT1",
                7 => "FIN_WAIT2",
                8 => "CLOSE_WAIT",
                9 => "CLOSING",
                10 => "LAST_ACK",
                11 => "TIME_WAIT",
                12 => "DELETE_TCB",
                _ => "UNKNOWN"
            };
        }

        private string ResolveHostname(string ipAndPort)
        {
            try
            {
                if (string.IsNullOrEmpty(ipAndPort))
                    return string.Empty;

                string ip = ipAndPort.Split(':')[0];

                if (dnsCache.ContainsKey(ip))
                {
                    var cached = dnsCache[ip];
                    if ((DateTime.Now - cached.Timestamp).TotalMinutes < 10)
                        return cached.Hostname;
                }

                // Use try/catch for DNS lookup - it can fail for many reasons
                string hostname;
                try
                {
                    var hostEntry = Dns.GetHostEntry(ip);
                    hostname = hostEntry.HostName;
                }
                catch
                {
                    // If reverse lookup fails, just return original ipAndPort
                    return ipAndPort;
                }
                
                dnsCache[ip] = new DnsCache
                {
                    Hostname = hostname,
                    Timestamp = DateTime.Now
                };

                // Определяем тип сервера по домену
                string serverType = DetermineServerType(hostname);
                return $"{hostname} ({serverType})";
            }
            catch
            {
                return ipAndPort;
            }
        }

        private string DetermineServerType(string hostname)
        {
            hostname = hostname.ToLower();

            if (hostname.Contains("cdn") || hostname.Contains("cloudfront") || hostname.Contains("fastly"))
                return "CDN";
            if (hostname.Contains("amazonaws") || hostname.Contains("azure") || hostname.Contains("google"))
                return "Cloud Server";
            if (hostname.Contains("api"))
                return "API Server";
            if (hostname.Contains("update") || hostname.Contains("patch"))
                return "Update Server";
            if (hostname.Contains("download") || hostname.Contains("dl"))
                return "Download Server";
            if (hostname.Contains("auth") || hostname.Contains("login"))
                return "Auth Server";
            if (hostname.Contains("game") || hostname.Contains("match"))
                return "Game Server";
            if (hostname.Contains("telemetry") || hostname.Contains("analytics") || hostname.Contains("metric"))
                return "Telemetry/Analytics";

            return "Web Server";
        }

        public List<NetworkConnection> GetConnections()
        {
            // Try to parse Timestamp (HH:mm:ss) into DateTime for reliable sorting
            return connections
                .OrderByDescending(c => DateTime.TryParse(c.Timestamp, out var t) ? DateTime.Today.Add(t.TimeOfDay) : DateTime.MinValue)
                .ToList();
        }

        public void ClearLog()
        {
            connections.Clear();
            dnsCache.Clear();
        }

        public string GetNetworkStatistics()
        {
            var sb = new StringBuilder();
            sb.AppendLine("═══════════════════════════════════════");
            sb.AppendLine("     СТАТИСТИКА СЕТИ");
            sb.AppendLine("═══════════════════════════════════════");
            sb.AppendLine($"Всего соединений: {connections.Count}");
            sb.AppendLine($"TCP соединений:   {connections.Count(c => c.Protocol == \"TCP\")}");
            sb.AppendLine($"UDP соединений:   {connections.Count(c => c.Protocol == \"UDP\")}");
            sb.AppendLine();

            var topDestinations = connections
                .GroupBy(c => c.Destination)
                .OrderByDescending(g => g.Count())
                .Take(10);

            sb.AppendLine("Топ-10 адресов назначения:");
            foreach (var dest in topDestinations)
            {
                sb.AppendLine($"  {dest.Key}: {dest.Count()} соединений");
            }

            return sb.ToString();
        }

        public List<DownloadInfo> GetDownloadedFiles()
        {
            // Анализ скачанных файлов по HTTP соединениям
            var downloads = new List<DownloadInfo>();

            var httpConnections = connections.Where(c =>
                (!string.IsNullOrEmpty(c.Destination) && (c.Destination.Contains(":80") || c.Destination.Contains(":443"))) ||
                (!string.IsNullOrEmpty(c.Url) && c.Url.Contains("http", StringComparison.OrdinalIgnoreCase)));

            foreach (var conn in httpConnections)
            {
                downloads.Add(new DownloadInfo
                {
                    Url = conn.Url ?? string.Empty,
                    Server = conn.Destination ?? string.Empty,
                    Protocol = conn.Protocol,
                    Timestamp = conn.Timestamp,
                    Status = "Detected"
                });
            }

            return downloads.GroupBy(d => d.Server).Select(g => g.First()).ToList();
        }

        public string ExportToLog(string filePath)
        {
            var sb = new StringBuilder();
            sb.AppendLine("════════════════════════════════════════════════════════");
            sb.AppendLine("           NETWORK MONITORING LOG");
            sb.AppendLine($"           Generated: {DateTime.Now}");
            sb.AppendLine("════════════════════════════════════════════════════════");
            sb.AppendLine();

            sb.AppendLine(GetNetworkStatistics());
            sb.AppendLine();

            sb.AppendLine("════════════════════════════════════════════════════════");
            sb.AppendLine("                ALL CONNECTIONS");
            sb.AppendLine("════════════════════════════════════════════════════════");
            sb.AppendLine();

            foreach (var conn in connections)
            {
                sb.AppendLine($"[{conn.Timestamp}] {conn.Protocol} | {conn.Source} -> {conn.Destination}");
                if (!string.IsNullOrEmpty(conn.Url))
                    sb.AppendLine($"  URL: {conn.Url}");
                sb.AppendLine($"  State: {conn.State}");
                sb.AppendLine();
            }

            System.IO.File.WriteAllText(filePath, sb.ToString());
            return sb.ToString();
        }
    }

    public class NetworkConnection
    {
        public string Protocol { get; set; } = string.Empty;
        public string Source { get; set; } = string.Empty;
        public string Destination { get; set; } = string.Empty;
        public string Url { get; set; } = string.Empty;
        public string Timestamp { get; set; } = string.Empty;
        public string Size { get; set; } = string.Empty;
        public string State { get; set; } = string.Empty;
        public int ProcessId { get; set; }
    }

    public class NetworkPacket
    {
        public string Protocol { get; set; } = string.Empty;
        public string Source { get; set; } = string.Empty;
        public string Destination { get; set; } = string.Empty;
        public string Url { get; set; } = string.Empty;
        public DateTime Timestamp { get; set; }
        public byte[] Data { get; set; } = Array.Empty<byte>();
    }

    public class DnsCache
    {
        public string Hostname { get; set; } = string.Empty;
        public DateTime Timestamp { get; set; }
    }

    public class DownloadInfo
    {
        public string Url { get; set; } = string.Empty;
        public string Server { get; set; } = string.Empty;
        public string Protocol { get; set; } = string.Empty;
        public string Timestamp { get; set; } = string.Empty;
        public string Status { get; set; } = string.Empty;
    }
}
