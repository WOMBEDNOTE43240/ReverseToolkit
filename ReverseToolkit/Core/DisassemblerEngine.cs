using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace ReverseToolkit
{
    /// <summary>
    /// Simplified Disassembler Engine (without SharpDisasm dependency)
    /// Shows hex bytes with basic instruction detection
    /// </summary>
    public class DisassemblerEngine
    {
        private byte[]? codeBytes;
        private long baseAddress;

        public string Disassemble(string architecture, long address, int size)
        {
            baseAddress = address;
            
            if (codeBytes == null || codeBytes.Length == 0)
                return "No data to disassemble.\nLoad a file or attach to a process.";

            try
            {
                return DisassembleBytes(codeBytes, address, size, architecture);
            }
            catch (Exception ex)
            {
                return $"Disassembly error: {ex.Message}";
            }
        }

        public void LoadCodeFromFile(byte[] data)
        {
            codeBytes = data;
        }

        public void LoadCodeFromMemory(byte[] data, long address)
        {
            codeBytes = data;
            baseAddress = address;
        }

        private string DisassembleBytes(byte[] bytes, long startAddress, int maxInstructions, string architecture)
        {
            var sb = new StringBuilder();
            sb.AppendLine("═══════════════════════════════════════════════════════════════════");
            sb.AppendLine($"  DISASSEMBLY - {architecture} mode - Address: 0x{startAddress:X}");
            sb.AppendLine("═══════════════════════════════════════════════════════════════════");
            sb.AppendLine();
            sb.AppendLine("NOTE: Full disassembly requires SharpDisasm library.");
            sb.AppendLine("      Currently showing hex dump with basic instruction hints.");
            sb.AppendLine();

            int instructionCount = 0;
            int offset = 0;
            int maxBytes = Math.Min(bytes.Length, maxInstructions * 15); // Estimate

            while (offset < maxBytes && instructionCount < maxInstructions)
            {
                long addr = startAddress + offset;
                
                // Read up to 15 bytes for instruction (max x86/x64 instruction length)
                int bytesToRead = Math.Min(15, bytes.Length - offset);
                byte[] instrBytes = new byte[bytesToRead];
                Array.Copy(bytes, offset, instrBytes, 0, bytesToRead);

                // Try to detect instruction length (simplified)
                int instrLen = DetectInstructionLength(instrBytes, architecture == "x64");
                
                // Format hex bytes
                string hexBytes = string.Join(" ", instrBytes.Take(instrLen).Select(b => b.ToString("X2")));
                string padding = new string(' ', Math.Max(0, 45 - hexBytes.Length));

                // Try to identify instruction type
                string mnemonic = IdentifyInstruction(instrBytes, architecture == "x64");

                sb.AppendLine($"0x{addr:X8}:  {hexBytes}{padding}{mnemonic}");

                offset += instrLen;
                instructionCount++;
            }

            sb.AppendLine();
            sb.AppendLine("═══════════════════════════════════════════════════════════════════");
            sb.AppendLine($"Total instructions: {instructionCount}");
            sb.AppendLine($"Bytes disassembled: {offset}");
            sb.AppendLine("═══════════════════════════════════════════════════════════════════");

            return sb.ToString();
        }

        private int DetectInstructionLength(byte[] bytes, bool is64bit)
        {
            if (bytes.Length == 0) return 1;

            // Very simplified instruction length detection
            byte opcode = bytes[0];

            // Common single-byte instructions
            if (opcode >= 0x40 && opcode <= 0x5F) return 1; // PUSH/POP regs (x86)
            if (opcode == 0x90) return 1; // NOP
            if (opcode == 0xC3) return 1; // RET
            if (opcode == 0xC9) return 1; // LEAVE
            if (opcode == 0xCC) return 1; // INT3

            // Two-byte instructions
            if (opcode == 0x0F && bytes.Length > 1) return 3; // Two-byte opcode

            // Instructions with ModR/M
            if (opcode >= 0x80 && opcode <= 0x8B) return 2; // Common ALU operations
            if (opcode == 0xFF || opcode == 0xFE) return 2; // INC/DEC/CALL/JMP

            // Call/Jump with immediate
            if (opcode == 0xE8 || opcode == 0xE9) return 5; // CALL/JMP rel32
            if (opcode >= 0x70 && opcode <= 0x7F) return 2; // Jcc short

            // MOV immediate to register
            if (opcode >= 0xB0 && opcode <= 0xB7) return 2; // MOV imm8 to r8
            if (opcode >= 0xB8 && opcode <= 0xBF) return 5; // MOV imm32 to r32

            // Default: assume 3 bytes (very rough estimate)
            return Math.Min(3, bytes.Length);
        }

        private string IdentifyInstruction(byte[] bytes, bool is64bit)
        {
            if (bytes.Length == 0) return "???";

            byte opcode = bytes[0];

            // Common instructions
            return opcode switch
            {
                0x90 => "nop",
                0xC3 => "ret",
                0xC9 => "leave",
                0xCC => "int3",
                0xE8 => "call rel32",
                0xE9 => "jmp rel32",
                0xFF => "call/jmp [mem]",
                >= 0x50 and <= 0x57 => $"push r{opcode - 0x50}",
                >= 0x58 and <= 0x5F => $"pop r{opcode - 0x58}",
                >= 0x70 and <= 0x7F => GetJccMnemonic(opcode),
                >= 0xB0 and <= 0xB7 => $"mov r{opcode - 0xB0}, imm8",
                >= 0xB8 and <= 0xBF => $"mov r{opcode - 0xB8}, imm32",
                0x89 => "mov [mem], reg",
                0x8B => "mov reg, [mem]",
                0xC7 => "mov [mem], imm32",
                0x48 when is64bit => "REX.W prefix",
                _ => $"[{opcode:X2}h]"
            };
        }

        private string GetJccMnemonic(byte opcode)
        {
            return (opcode & 0x0F) switch
            {
                0x00 => "jo short",
                0x01 => "jno short",
                0x02 => "jb short",
                0x03 => "jae short",
                0x04 => "je short",
                0x05 => "jne short",
                0x06 => "jbe short",
                0x07 => "ja short",
                0x08 => "js short",
                0x09 => "jns short",
                0x0A => "jp short",
                0x0B => "jnp short",
                0x0C => "jl short",
                0x0D => "jge short",
                0x0E => "jle short",
                0x0F => "jg short",
                _ => "jcc short"
            };
        }

        public string GetStatistics()
        {
            if (codeBytes == null)
                return "No code loaded";

            var sb = new StringBuilder();
            sb.AppendLine("═══════════════════════════════════════════════");
            sb.AppendLine("  CODE STATISTICS");
            sb.AppendLine("═══════════════════════════════════════════════");
            sb.AppendLine($"Base Address: 0x{baseAddress:X}");
            sb.AppendLine($"Code Size: {codeBytes.Length} bytes");
            sb.AppendLine($"Code Range: 0x{baseAddress:X} - 0x{baseAddress + codeBytes.Length:X}");
            sb.AppendLine();

            // Count instruction types (simplified)
            var instructionTypes = new Dictionary<string, int>();
            for (int i = 0; i < Math.Min(codeBytes.Length, 1000); i++)
            {
                byte opcode = codeBytes[i];
                string type = GetInstructionType(opcode);
                instructionTypes[type] = instructionTypes.GetValueOrDefault(type) + 1;
            }

            sb.AppendLine("Top Instruction Types (first 1000 bytes):");
            foreach (var kvp in instructionTypes.OrderByDescending(x => x.Value).Take(10))
            {
                sb.AppendLine($"  {kvp.Key,-20} {kvp.Value,5} times");
            }

            sb.AppendLine("═══════════════════════════════════════════════");
            return sb.ToString();
        }

        private string GetInstructionType(byte opcode)
        {
            return opcode switch
            {
                >= 0x50 and <= 0x5F => "PUSH/POP",
                >= 0x70 and <= 0x7F => "Conditional Jump",
                >= 0x80 and <= 0x8F => "ALU Operations",
                >= 0xB0 and <= 0xBF => "MOV Immediate",
                0xE8 or 0xE9 => "CALL/JMP",
                0xFF or 0xFE => "INC/DEC/CALL",
                0xC3 or 0xC2 => "RET",
                0x90 => "NOP",
                0xCC => "INT3",
                _ => "Other"
            };
        }

        public List<string> FindFunctions()
        {
            var functions = new List<string>();

            if (codeBytes == null || codeBytes.Length == 0)
            {
                functions.Add("No code loaded");
                return functions;
            }

            functions.Add("═══════════════════════════════════════════════");
            functions.Add("  FUNCTION DETECTION (Simplified)");
            functions.Add("═══════════════════════════════════════════════");
            functions.Add("");
            functions.Add("NOTE: Full function analysis requires SharpDisasm library.");
            functions.Add("      Currently detecting function prologs only.");
            functions.Add("");

            // Look for common function prologs
            int functionCount = 0;
            for (int i = 0; i < codeBytes.Length - 3; i++)
            {
                // Common x86/x64 function prologs:
                // 55 8B EC          : push ebp; mov ebp, esp
                // 48 89 5C 24       : REX.W mov [rsp+XX], rbx (x64)
                // 40 53             : REX push rbx (x64)
                
                if (codeBytes[i] == 0x55 && i + 2 < codeBytes.Length &&
                    codeBytes[i + 1] == 0x8B && codeBytes[i + 2] == 0xEC)
                {
                    functions.Add($"Function @ 0x{baseAddress + i:X8}  (x86 prolog: push ebp; mov ebp, esp)");
                    functionCount++;
                    i += 2;
                }
                else if (codeBytes[i] == 0x48 && i + 3 < codeBytes.Length &&
                         codeBytes[i + 1] == 0x89 && codeBytes[i + 2] == 0x5C)
                {
                    functions.Add($"Function @ 0x{baseAddress + i:X8}  (x64 prolog: mov [rsp+XX], rbx)");
                    functionCount++;
                    i += 3;
                }
            }

            functions.Add("");
            functions.Add($"Found {functionCount} potential functions");
            functions.Add("═══════════════════════════════════════════════");

            return functions;
        }
    }
}
