using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace ReverseToolkit
{
    public class HexEditorEngine
    {
        private byte[]? fileData;
        private string? currentFilePath;
        private int currentOffset;
        private const int BytesPerLine = 16;
        private const int MaxDisplayLines = 10000; // Limit for performance

        public void LoadFile(string path)
        {
            currentFilePath = path;
            fileData = File.ReadAllBytes(path);
            currentOffset = 0;
        }

        public string GetHexView()
        {
            if (fileData == null || fileData.Length == 0)
                return "Нет загруженных данных";

            var sb = new StringBuilder();
            int totalLines = Math.Min((fileData.Length + BytesPerLine - 1) / BytesPerLine, MaxDisplayLines);
            
            // Header
            sb.AppendLine("Offset(h)  00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F  Decoded text");
            sb.AppendLine("═══════════════════════════════════════════════════════════════════════════════");

            for (int line = 0; line < totalLines; line++)
            {
                int offset = line * BytesPerLine;
                sb.Append($"{offset:X8}   ");

                // Hex bytes
                var asciiBuilder = new StringBuilder();
                for (int i = 0; i < BytesPerLine; i++)
                {
                    int pos = offset + i;
                    if (pos < fileData.Length)
                    {
                        byte b = fileData[pos];
                        sb.Append($"{b:X2} ");
                        
                        // ASCII representation
                        if (b >= 32 && b <= 126)
                            asciiBuilder.Append((char)b);
                        else
                            asciiBuilder.Append('.');
                    }
                    else
                    {
                        sb.Append("   ");
                        asciiBuilder.Append(' ');
                    }
                }

                sb.Append(" ");
                sb.Append(asciiBuilder.ToString());
                sb.AppendLine();
            }

            if (fileData.Length > MaxDisplayLines * BytesPerLine)
            {
                sb.AppendLine();
                sb.AppendLine($"... ({fileData.Length - (MaxDisplayLines * BytesPerLine)} байт не отображено для производительности)");
                sb.AppendLine("Используйте функцию 'Перейти к offset' для навигации");
            }

            return sb.ToString();
        }

        public void GoToOffset(int offset)
        {
            if (fileData == null)
                return;

            currentOffset = Math.Max(0, Math.Min(offset, fileData.Length - 1));
        }

        public List<int> Search(string pattern)
        {
            var results = new List<int>();
            
            if (fileData == null || string.IsNullOrEmpty(pattern))
                return results;

            // Try to parse as hex pattern
            if (IsHexPattern(pattern))
            {
                var searchBytes = ParseHexPattern(pattern);
                results = SearchBytes(searchBytes);
            }
            else
            {
                // Search as ASCII string
                var searchBytes = Encoding.ASCII.GetBytes(pattern);
                results = SearchBytes(searchBytes);
            }

            return results;
        }

        private bool IsHexPattern(string pattern)
        {
            pattern = pattern.Replace(" ", "").Replace("0x", "");
            return pattern.All(c => "0123456789ABCDEFabcdef".Contains(c));
        }

        private byte[] ParseHexPattern(string pattern)
        {
            pattern = pattern.Replace(" ", "").Replace("0x", "");
            
            if (pattern.Length % 2 != 0)
                pattern = "0" + pattern;

            byte[] bytes = new byte[pattern.Length / 2];
            for (int i = 0; i < bytes.Length; i++)
            {
                bytes[i] = Convert.ToByte(pattern.Substring(i * 2, 2), 16);
            }

            return bytes;
        }

        private List<int> SearchBytes(byte[] searchPattern)
        {
            var results = new List<int>();
            
            if (fileData == null || searchPattern == null || searchPattern.Length == 0)
                return results;

            for (int i = 0; i <= fileData.Length - searchPattern.Length; i++)
            {
                bool found = true;
                for (int j = 0; j < searchPattern.Length; j++)
                {
                    if (fileData[i + j] != searchPattern[j])
                    {
                        found = false;
                        break;
                    }
                }

                if (found)
                {
                    results.Add(i);
                    
                    // Limit results to prevent UI freeze
                    if (results.Count >= 1000)
                        break;
                }
            }

            return results;
        }

        public void SaveFile(string path, string hexViewText)
        {
            if (fileData == null)
                throw new InvalidOperationException("No data loaded");

            // Parse hex view back to bytes
            var modifiedData = ParseHexView(hexViewText);
            
            if (modifiedData != null && modifiedData.Length > 0)
            {
                File.WriteAllBytes(path, modifiedData);
                fileData = modifiedData;
            }
        }

        private byte[]? ParseHexView(string hexView)
        {
            if (fileData == null)
                return null;

            var lines = hexView.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
            var bytesList = new List<byte>();

            foreach (var line in lines)
            {
                // Skip header and separator lines
                if (line.Contains("Offset(h)") || line.Contains("═") || 
                    line.Contains("...") || line.Contains("байт не отображено"))
                    continue;

                // Extract hex bytes from line
                // Format: "00000000   4D 5A 90 00 ..."
                var parts = line.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
                
                if (parts.Length < 2)
                    continue;

                // Skip offset (first part)
                for (int i = 1; i < parts.Length; i++)
                {
                    var part = parts[i].Trim();
                    
                    // Stop at ASCII section
                    if (part.Length != 2)
                        break;

                    try
                    {
                        byte b = Convert.ToByte(part, 16);
                        bytesList.Add(b);
                    }
                    catch
                    {
                        // Invalid hex, stop parsing this line
                        break;
                    }
                }
            }

            return bytesList.Count > 0 ? bytesList.ToArray() : fileData;
        }

        public string GetHexViewAtOffset(int offset, int size)
        {
            if (fileData == null)
                return "Нет загруженных данных";

            offset = Math.Max(0, Math.Min(offset, fileData.Length - 1));
            size = Math.Min(size, fileData.Length - offset);

            var sb = new StringBuilder();
            sb.AppendLine($"Просмотр с offset 0x{offset:X8}, размер: {size} байт");
            sb.AppendLine("Offset(h)  00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F  Decoded text");
            sb.AppendLine("═══════════════════════════════════════════════════════════════════════════════");

            int lines = (size + BytesPerLine - 1) / BytesPerLine;
            
            for (int line = 0; line < lines; line++)
            {
                int currentOffset = offset + (line * BytesPerLine);
                sb.Append($"{currentOffset:X8}   ");

                var asciiBuilder = new StringBuilder();
                for (int i = 0; i < BytesPerLine; i++)
                {
                    int pos = currentOffset + i;
                    if (pos < offset + size && pos < fileData.Length)
                    {
                        byte b = fileData[pos];
                        sb.Append($"{b:X2} ");
                        
                        if (b >= 32 && b <= 126)
                            asciiBuilder.Append((char)b);
                        else
                            asciiBuilder.Append('.');
                    }
                    else
                    {
                        sb.Append("   ");
                        asciiBuilder.Append(' ');
                    }
                }

                sb.Append(" ");
                sb.Append(asciiBuilder.ToString());
                sb.AppendLine();
            }

            return sb.ToString();
        }

        public byte[]? GetBytesAtOffset(int offset, int size)
        {
            if (fileData == null)
                return null;

            offset = Math.Max(0, Math.Min(offset, fileData.Length - 1));
            size = Math.Min(size, fileData.Length - offset);

            byte[] result = new byte[size];
            Array.Copy(fileData, offset, result, 0, size);
            return result;
        }

        public bool ModifyBytesAtOffset(int offset, byte[] newBytes)
        {
            if (fileData == null || newBytes == null || offset < 0 || offset + newBytes.Length > fileData.Length)
                return false;

            Array.Copy(newBytes, 0, fileData, offset, newBytes.Length);
            return true;
        }

        public string GetFileInfo()
        {
            if (fileData == null || string.IsNullOrEmpty(currentFilePath))
                return "No file loaded";

            var sb = new StringBuilder();
            sb.AppendLine("═══════════════════════════════════════════");
            sb.AppendLine("         ИНФОРМАЦИЯ О ФАЙЛЕ");
            sb.AppendLine("═══════════════════════════════════════════");
            sb.AppendLine($"Файл:     {Path.GetFileName(currentFilePath)}");
            sb.AppendLine($"Путь:     {currentFilePath}");
            sb.AppendLine($"Размер:   {fileData.Length:N0} байт ({FormatFileSize(fileData.Length)})");
            
            if (File.Exists(currentFilePath))
            {
                var fileInfo = new FileInfo(currentFilePath);
                sb.AppendLine($"Создан:   {fileInfo.CreationTime}");
                sb.AppendLine($"Изменен:  {fileInfo.LastWriteTime}");
            }

            // File signature detection
            string signature = DetectFileSignature();
            if (!string.IsNullOrEmpty(signature))
            {
                sb.AppendLine($"Тип:      {signature}");
            }

            return sb.ToString();
        }

        private string DetectFileSignature()
        {
            if (fileData == null || fileData.Length < 4)
                return "Unknown";

            // Check common file signatures
            if (fileData[0] == 0x4D && fileData[1] == 0x5A)
                return "PE Executable (MZ)";
            
            if (fileData[0] == 0x7F && fileData[1] == 0x45 && fileData[2] == 0x4C && fileData[3] == 0x46)
                return "ELF Executable";
            
            if (fileData[0] == 0x50 && fileData[1] == 0x4B)
                return "ZIP/JAR Archive";
            
            if (fileData[0] == 0x89 && fileData[1] == 0x50 && fileData[2] == 0x4E && fileData[3] == 0x47)
                return "PNG Image";
            
            if (fileData[0] == 0xFF && fileData[1] == 0xD8 && fileData[2] == 0xFF)
                return "JPEG Image";
            
            if (fileData[0] == 0x47 && fileData[1] == 0x49 && fileData[2] == 0x46)
                return "GIF Image";
            
            if (fileData[0] == 0x25 && fileData[1] == 0x50 && fileData[2] == 0x44 && fileData[3] == 0x46)
                return "PDF Document";

            return "Unknown";
        }

        private string FormatFileSize(long bytes)
        {
            string[] sizes = { "B", "KB", "MB", "GB", "TB" };
            double len = bytes;
            int order = 0;
            
            while (len >= 1024 && order < sizes.Length - 1)
            {
                order++;
                len = len / 1024;
            }

            return $"{len:0.##} {sizes[order]}";
        }

        public Dictionary<string, int> GetByteStatistics()
        {
            var stats = new Dictionary<string, int>();
            
            if (fileData == null)
                return stats;

            var byteCounts = new int[256];
            foreach (byte b in fileData)
            {
                byteCounts[b]++;
            }

            stats["Null Bytes (0x00)"] = byteCounts[0];
            stats["Printable ASCII"] = byteCounts.Where((count, index) => index >= 32 && index <= 126).Sum();
            stats["High Bytes (>0x7F)"] = byteCounts.Where((count, index) => index > 127).Sum();
            stats["Unique Bytes"] = byteCounts.Count(c => c > 0);

            return stats;
        }
    }
}
