using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

namespace ReverseToolkit
{
    public class MemoryScanner
    {
        private Process? attachedProcess;
        private IntPtr processHandle = IntPtr.Zero;
        private List<MemoryResult> currentResults = new();
        private Dictionary<long, string> frozenAddresses = new();
        private Thread? freezeThread;
        private bool isFreezingActive;

        // Windows API imports
        [DllImport("kernel32.dll")]
        private static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll")]
        private static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int dwSize, out int lpNumberOfBytesRead);

        [DllImport("kernel32.dll")]
        private static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int nSize, out int lpNumberOfBytesWritten);

        [DllImport("kernel32.dll")]
        private static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll")]
        private static extern int VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);

        private const int PROCESS_ALL_ACCESS = 0x1F0FFF;
        private const int MEM_COMMIT = 0x1000;
        private const int PAGE_READWRITE = 0x04;
        private const int PAGE_EXECUTE_READWRITE = 0x40;
        private const int PAGE_READONLY = 0x02;

        [StructLayout(LayoutKind.Sequential)]
        private struct MEMORY_BASIC_INFORMATION
        {
            public IntPtr BaseAddress;
            public IntPtr AllocationBase;
            public uint AllocationProtect;
            public IntPtr RegionSize;
            public uint State;
            public uint Protect;
            public uint Type;
        }

        public List<ProcessInfo> GetProcessList()
        {
            var processes = Process.GetProcesses()
                .Where(p => !string.IsNullOrEmpty(p.MainWindowTitle) || p.WorkingSet64 > 1024 * 1024)
                .OrderBy(p => p.ProcessName)
                .Select(p => new ProcessInfo
                {
                    Id = p.Id,
                    Name = p.ProcessName,
                    DisplayName = $"{p.ProcessName} (PID: {p.Id}) - {FormatMemorySize(p.WorkingSet64)}"
                })
                .ToList();

            return processes;
        }

        public void AttachToProcess(int processId)
        {
            try
            {
                if (processHandle != IntPtr.Zero)
                {
                    CloseHandle(processHandle);
                }

                attachedProcess = Process.GetProcessById(processId);
                processHandle = OpenProcess(PROCESS_ALL_ACCESS, false, processId);

                if (processHandle == IntPtr.Zero)
                {
                    throw new Exception("Failed to access process. Administrator rights required.");
                }

                currentResults.Clear();
            }
            catch (Exception ex)
            {
                throw new Exception($"Process attachment error: {ex.Message}");
            }
        }

        public List<MemoryResult> FirstScan(string scanType, string valueType, string value)
        {
            if (processHandle == IntPtr.Zero)
                throw new Exception("Process not attached");

            currentResults.Clear();
            var regions = GetMemoryRegions();

            foreach (var region in regions)
            {
                ScanRegion(region, scanType, valueType, value);
            }

            return currentResults;
        }

        public List<MemoryResult> NextScan(string value)
        {
            if (processHandle == IntPtr.Zero || currentResults.Count == 0)
                return currentResults;

            var updatedResults = new List<MemoryResult>();

            foreach (var result in currentResults)
            {
                byte[] buffer = new byte[GetTypeSize(result.Type)];
                if (ReadProcessMemory(processHandle, (IntPtr)result.Address, buffer, buffer.Length, out _))
                {
                    string currentValue = ParseValue(buffer, result.Type);
                    
                    if (currentValue == value)
                    {
                        result.PreviousValue = result.Value;
                        result.Value = currentValue;
                        updatedResults.Add(result);
                    }
                }
            }

            currentResults = updatedResults;
            return currentResults;
        }

        private List<MEMORY_BASIC_INFORMATION> GetMemoryRegions()
        {
            var regions = new List<MEMORY_BASIC_INFORMATION>();
            IntPtr address = IntPtr.Zero;
            
            if (attachedProcess == null)
                return regions;

            long maxAddress = attachedProcess.MainModule?.BaseAddress.ToInt64() ?? 0;
            maxAddress += 0x7FFFFFFF; // Scan up to ~2GB

            while (address.ToInt64() < maxAddress)
            {
                MEMORY_BASIC_INFORMATION mbi;
                int result = VirtualQueryEx(processHandle, address, out mbi, (uint)Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION)));

                if (result == 0)
                    break;

                // Only scan committed, readable memory
                if (mbi.State == MEM_COMMIT && 
                    (mbi.Protect == PAGE_READWRITE || 
                     mbi.Protect == PAGE_EXECUTE_READWRITE ||
                     mbi.Protect == PAGE_READONLY) &&
                    mbi.RegionSize.ToInt64() < 100 * 1024 * 1024) // Skip regions > 100MB
                {
                    regions.Add(mbi);
                }

                address = new IntPtr(mbi.BaseAddress.ToInt64() + mbi.RegionSize.ToInt64());
            }

            return regions;
        }

        private void ScanRegion(MEMORY_BASIC_INFORMATION region, string scanType, string valueType, string value)
        {
            int regionSize = (int)Math.Min(region.RegionSize.ToInt64(), int.MaxValue);
            byte[] buffer = new byte[regionSize];

            if (!ReadProcessMemory(processHandle, region.BaseAddress, buffer, regionSize, out int bytesRead))
                return;

            int typeSize = GetTypeSize(valueType);
            int maxResults = 10000; // Limit results

            for (int i = 0; i <= bytesRead - typeSize && currentResults.Count < maxResults; i++)
            {
                byte[] valueBytes = new byte[typeSize];
                Array.Copy(buffer, i, valueBytes, 0, typeSize);

                string scannedValue = ParseValue(valueBytes, valueType);
                
                if (scanType == "Exact Value" && scannedValue == value)
                {
                    currentResults.Add(new MemoryResult
                    {
                        Address = region.BaseAddress.ToInt64() + i,
                        Value = scannedValue,
                        PreviousValue = scannedValue,
                        Type = valueType
                    });
                }
                else if (scanType == "Unknown Value")
                {
                    currentResults.Add(new MemoryResult
                    {
                        Address = region.BaseAddress.ToInt64() + i,
                        Value = scannedValue,
                        PreviousValue = scannedValue,
                        Type = valueType
                    });
                }
            }
        }

        private int GetTypeSize(string valueType)
        {
            return valueType switch
            {
                "Int32" => 4,
                "Int64" => 8,
                "Float" => 4,
                "Double" => 8,
                "String" => 32,
                "Bytes" => 16,
                _ => 4
            };
        }

        private string ParseValue(byte[] bytes, string valueType)
        {
            try
            {
                return valueType switch
                {
                    "Int32" => BitConverter.ToInt32(bytes, 0).ToString(),
                    "Int64" => BitConverter.ToInt64(bytes, 0).ToString(),
                    "Float" => BitConverter.ToSingle(bytes, 0).ToString("F2"),
                    "Double" => BitConverter.ToDouble(bytes, 0).ToString("F2"),
                    "String" => Encoding.ASCII.GetString(bytes).TrimEnd('\0'),
                    "Bytes" => BitConverter.ToString(bytes).Replace("-", " "),
                    _ => "?"
                };
            }
            catch
            {
                return "?";
            }
        }

        public void ModifyMemory(long address, string newValue)
        {
            if (processHandle == IntPtr.Zero)
                return;

            var result = currentResults.FirstOrDefault(r => r.Address == address);
            if (result == null)
                return;

            byte[] newBytes = ConvertValueToBytes(newValue, result.Type);
            
            if (WriteProcessMemory(processHandle, (IntPtr)address, newBytes, newBytes.Length, out _))
            {
                result.PreviousValue = result.Value;
                result.Value = newValue;
            }
        }

        public void FreezeMemory(long address, string value)
        {
            frozenAddresses[address] = value;

            if (!isFreezingActive)
            {
                isFreezingActive = true;
                freezeThread = new Thread(FreezeLoop);
                freezeThread.IsBackground = true;
                freezeThread.Start();
            }
        }

        public void UnfreezeMemory(long address)
        {
            frozenAddresses.Remove(address);
        }

        private void FreezeLoop()
        {
            while (isFreezingActive && frozenAddresses.Count > 0)
            {
                // Если процесс недоступен — ждём и повторяем
                if (processHandle == IntPtr.Zero)
                {
                    Thread.Sleep(200);
                    continue;
                }

                foreach (var frozen in frozenAddresses.ToList())
                {
                    var result = currentResults.FirstOrDefault(r => r.Address == frozen.Key);
                    if (result != null)
                    {
                        byte[] bytes = ConvertValueToBytes(frozen.Value, result.Type);
                        // Пишем только если есть действительный handle
                        if (processHandle != IntPtr.Zero)
                        {
                            WriteProcessMemory(processHandle, (IntPtr)frozen.Key, bytes, bytes.Length, out _);
                        }
                    }
                }

                Thread.Sleep(100); // Update every 100ms
            }

            // Останавливаем флаг при выходе
            isFreezingActive = false;
        }

        private byte[] ConvertValueToBytes(string value, string valueType)
        {
            try
            {
                byte[] raw;
                switch (valueType)
                {
                    case "Int32":
                        raw = BitConverter.GetBytes(int.Parse(value));
                        break;
                    case "Int64":
                        raw = BitConverter.GetBytes(long.Parse(value));
                        break;
                    case "Float":
                        raw = BitConverter.GetBytes(float.Parse(value));
                        break;
                    case "Double":
                        raw = BitConverter.GetBytes(double.Parse(value));
                        break;
                    case "String":
                        raw = Encoding.ASCII.GetBytes(value);
                        break;
                    case "Bytes":
                        raw = ParseHexString(value);
                        break;
                    default:
                        raw = new byte[4];
                        break;
                }

                int targetSize = GetTypeSize(valueType);
                if (raw.Length == targetSize)
                    return raw;

                var result = new byte[targetSize];
                Array.Copy(raw, 0, result, 0, Math.Min(raw.Length, targetSize));
                return result;
            }
            catch
            {
                return new byte[GetTypeSize(valueType)];
            }
        }

        private byte[] ParseHexString(string hex)
        {
            hex = (hex ?? string.Empty).Replace(" ", "").Replace("-", "");
            if (hex.Length == 0)
                return Array.Empty<byte>();

            if (hex.Length % 2 != 0)
                hex = "0" + hex; // дополняем ведущим нулём

            byte[] bytes = new byte[hex.Length / 2];

            for (int i = 0; i < bytes.Length; i++)
            {
                bytes[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
            }

            return bytes;
        }

        private string FormatMemorySize(long bytes)
        {
            string[] sizes = { "B", "KB", "MB", "GB" };
            double len = bytes;
            int order = 0;

            while (len >= 1024 && order < sizes.Length - 1)
            {
                order++;
                len = len / 1024;
            }

            return $"{len:0.##} {sizes[order]}";
        }

        public void Dispose()
        {
            isFreezingActive = false;
            frozenAddresses.Clear();
            
            if (processHandle != IntPtr.Zero)
            {
                CloseHandle(processHandle);
                processHandle = IntPtr.Zero;
            }
        }
    }

    public class ProcessInfo
    {
        public int Id { get; set; }
        public string Name { get; set; } = string.Empty;
        public string DisplayName { get; set; } = string.Empty;

        public override string ToString() => DisplayName;
    }

    public class MemoryResult
    {
        public long Address { get; set; }
        public string Value { get; set; } = string.Empty;
        public string PreviousValue { get; set; } = string.Empty;
        public string Type { get; set; } = string.Empty;
    }
}
