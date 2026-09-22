using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace ReverseToolkit
{
    public class PatternScanner
    {
        private byte[]? targetData;
        private List<PatternResult> lastResults = new();

        public List<PatternResult> SearchPattern(string pattern, bool inMemory = false)
        {
            lastResults.Clear();

            if (string.IsNullOrWhiteSpace(pattern))
                return lastResults;

            // Parse pattern (supports wildcards with ?)
            var patternInfo = ParsePattern(pattern);
            
            if (patternInfo.Bytes.Length == 0)
                return lastResults;

            if (targetData == null || targetData.Length == 0)
                return lastResults;

            // Search for pattern
            for (int i = 0; i <= targetData.Length - patternInfo.Bytes.Length; i++)
            {
                if (MatchesPattern(targetData, i, patternInfo))
                {
                    lastResults.Add(new PatternResult
                    {
                        Address = $"0x{i:X8}",
                        Pattern = pattern,
                        Context = GetContext(targetData, i, patternInfo.Bytes.Length)
                    });

                    // Limit results
                    if (lastResults.Count >= 1000)
                        break;
                }
            }

            return lastResults;
        }

        public void SetTargetData(byte[] data)
        {
            targetData = data;
        }

        private PatternInfo ParsePattern(string pattern)
        {
            // Remove extra spaces and normalize
            pattern = pattern.Trim().Replace("  ", " ");
            var parts = pattern.Split(' ');
            
            var bytes = new List<byte>();
            var wildcards = new List<bool>();

            foreach (var part in parts)
            {
                if (part == "?" || part == "??")
                {
                    bytes.Add(0);
                    wildcards.Add(true);
                }
                else
                {
                    try
                    {
                        bytes.Add(Convert.ToByte(part, 16));
                        wildcards.Add(false);
                    }
                    catch
                    {
                        // Invalid hex, skip
                    }
                }
            }

            return new PatternInfo
            {
                Bytes = bytes.ToArray(),
                Wildcards = wildcards.ToArray()
            };
        }

        private bool MatchesPattern(byte[] data, int offset, PatternInfo pattern)
        {
            for (int i = 0; i < pattern.Bytes.Length; i++)
            {
                if (offset + i >= data.Length)
                    return false;

                // Skip wildcard bytes
                if (pattern.Wildcards[i])
                    continue;

                if (data[offset + i] != pattern.Bytes[i])
                    return false;
            }

            return true;
        }

        private string GetContext(byte[] data, int offset, int patternLength)
        {
            const int contextBytes = 16;
            int start = Math.Max(0, offset - contextBytes);
            int end = Math.Min(data.Length, offset + patternLength + contextBytes);
            
            var sb = new StringBuilder();
            
            for (int i = start; i < end; i++)
            {
                // Highlight the matched pattern
                if (i >= offset && i < offset + patternLength)
                    sb.Append($"[{data[i]:X2}] ");
                else
                    sb.Append($"{data[i]:X2} ");
            }

            return sb.ToString().Trim();
        }

        public string GenerateSignature(byte[] data, int offset, int length, List<int>? wildcardOffsets = null)
        {
            if (data == null || offset < 0 || offset + length > data.Length)
                return string.Empty;

            var sb = new StringBuilder();
            wildcardOffsets ??= new List<int>();

            for (int i = 0; i < length; i++)
            {
                if (wildcardOffsets.Contains(i))
                    sb.Append("? ");
                else
                    sb.Append($"{data[offset + i]:X2} ");
            }

            return sb.ToString().Trim();
        }

        public List<PatternResult> FindAOBSignature(string aobPattern)
        {
            // AOB (Array of Bytes) pattern search
            // Supports formats like: "48 8B 05 ? ? ? ? 48 85 C0"
            return SearchPattern(aobPattern);
        }

        public Dictionary<string, List<int>> FindCommonPatterns()
        {
            var commonPatterns = new Dictionary<string, List<int>>();

            if (targetData == null || targetData.Length == 0)
                return commonPatterns;

            // Common patterns to search for
            var patterns = new Dictionary<string, string>
            {
                ["CALL instruction (x64)"] = "E8 ? ? ? ?",
                ["JMP instruction (x64)"] = "E9 ? ? ? ?",
                ["MOV RAX, [rel]"] = "48 8B 05 ? ? ? ?",
                ["MOV RCX, [rel]"] = "48 8B 0D ? ? ? ?",
                ["LEA instruction"] = "48 8D",
                ["PUSH RBP"] = "55",
                ["MOV RBP, RSP"] = "48 89 E5",
                ["Function prologue (x64)"] = "55 48 89 E5",
                ["RET instruction"] = "C3",
                ["NOP instruction"] = "90",
                ["INT3 breakpoint"] = "CC"
            };

            foreach (var kvp in patterns)
            {
                var results = SearchPattern(kvp.Value);
                if (results.Count > 0)
                {
                    commonPatterns[kvp.Key] = results.Select(r => Convert.ToInt32(r.Address.Replace("0x", ""), 16)).ToList();
                }
            }

            return commonPatterns;
        }

        public string AnalyzeByteFrequency()
        {
            if (targetData == null || targetData.Length == 0)
                return "No data for analysis";

            var frequency = new int[256];
            foreach (byte b in targetData)
            {
                frequency[b]++;
            }

            var sb = new StringBuilder();
            sb.AppendLine("═══════════════════════════════════════");
            sb.AppendLine("    АНАЛИЗ ЧАСТОТЫ БАЙТОВ");
            sb.AppendLine("═══════════════════════════════════════");
            sb.AppendLine();

            // Top 10 most common bytes
            var topBytes = frequency
                .Select((count, index) => new { Byte = (byte)index, Count = count })
                .OrderByDescending(x => x.Count)
                .Take(10);

            sb.AppendLine("Топ-10 наиболее частых байтов:");
            foreach (var item in topBytes)
            {
                double percentage = (item.Count * 100.0) / targetData.Length;
                sb.AppendLine($"  0x{item.Byte:X2}: {item.Count,10:N0} раз ({percentage:F2}%)");
            }

            sb.AppendLine();
            sb.AppendLine("Статистика:");
            sb.AppendLine($"  Всего байт:        {targetData.Length:N0}");
            sb.AppendLine($"  Уникальных байт:   {frequency.Count(c => c > 0)}");
            sb.AppendLine($"  Нулевых байт:      {frequency[0]:N0}");
            sb.AppendLine($"  Entropy:           {CalculateEntropy(frequency):F2} bits");

            return sb.ToString();
        }

        private double CalculateEntropy(int[] frequency)
        {
            double entropy = 0;
            int total = frequency.Sum();

            if (total == 0)
                return 0;

            foreach (int count in frequency)
            {
                if (count > 0)
                {
                    double probability = (double)count / total;
                    entropy -= probability * Math.Log(probability, 2);
                }
            }

            return entropy;
        }

        public List<SequenceInfo> FindRepeatingSequences(int minLength = 4, int minOccurrences = 2)
        {
            var sequences = new Dictionary<string, SequenceInfo>();

            if (targetData == null || targetData.Length < minLength)
                return new List<SequenceInfo>();

            // Search for repeating sequences
            for (int length = minLength; length <= 16; length++)
            {
                for (int i = 0; i <= targetData.Length - length; i++)
                {
                    var sequence = new byte[length];
                    Array.Copy(targetData, i, sequence, 0, length);
                    
                    string key = BitConverter.ToString(sequence);
                    
                    if (!sequences.ContainsKey(key))
                    {
                        sequences[key] = new SequenceInfo
                        {
                            Sequence = key,
                            Length = length,
                            Occurrences = new List<int>()
                        };
                    }
                    
                    sequences[key].Occurrences.Add(i);
                }
            }

            return sequences.Values
                .Where(s => s.Occurrences.Count >= minOccurrences)
                .OrderByDescending(s => s.Occurrences.Count)
                .ThenByDescending(s => s.Length)
                .Take(50)
                .ToList();
        }
    }

    public class PatternInfo
    {
        public byte[] Bytes { get; set; } = Array.Empty<byte>();
        public bool[] Wildcards { get; set; } = Array.Empty<bool>();
    }

    public class PatternResult
    {
        public string Address { get; set; } = string.Empty;
        public string Pattern { get; set; } = string.Empty;
        public string Context { get; set; } = string.Empty;
    }

    public class SequenceInfo
    {
        public string Sequence { get; set; } = string.Empty;
        public int Length { get; set; }
        public List<int> Occurrences { get; set; } = new();
    }
}
