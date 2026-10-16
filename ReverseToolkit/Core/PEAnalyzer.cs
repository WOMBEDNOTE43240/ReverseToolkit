using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace ReverseToolkit
{
    public class PEAnalyzer
    {
        private byte[]? fileData;
        private string? filePath;
        private PEHeader? peHeader;

        public void LoadPEFile(string path)
        {
            filePath = path;
            fileData = File.ReadAllBytes(path);
            peHeader = ParsePEHeader(fileData);
        }

        private static ushort ReadUInt16Safe(byte[] data, int offset)
        {
            if (offset < 0 || offset + 2 > data.Length)
                throw new InvalidDataException("Unexpected end of file while reading UInt16");
            return BitConverter.ToUInt16(data, offset);
        }

        private static uint ReadUInt32Safe(byte[] data, int offset)
        {
            if (offset < 0 || offset + 4 > data.Length)
                throw new InvalidDataException("Unexpected end of file while reading UInt32");
            return BitConverter.ToUInt32(data, offset);
        }

        private static ulong ReadUInt64Safe(byte[] data, int offset)
        {
            if (offset < 0 || offset + 8 > data.Length)
                throw new InvalidDataException("Unexpected end of file while reading UInt64");
            return BitConverter.ToUInt64(data, offset);
        }

        private PEHeader ParsePEHeader(byte[] data)
        {
            var header = new PEHeader();

            // DOS Header
            if (data.Length < 64)
                throw new InvalidDataException("File too small for PE format");

            // Check DOS signature "MZ"
            if (data[0] != 0x4D || data[1] != 0x5A)
                throw new InvalidDataException("Invalid DOS signature");

            // Get PE header offset
            int peOffset = (int)ReadUInt32Safe(data, 0x3C);

            if (peOffset + 4 >= data.Length)
                throw new InvalidDataException("Invalid PE offset");

            // Check PE signature "PE\0\0"
            if (data[peOffset] != 0x50 || data[peOffset + 1] != 0x45 || data[peOffset + 2] != 0x00 || data[peOffset + 3] != 0x00)
                throw new InvalidDataException("Invalid PE signature");

            header.PEOffset = peOffset;

            // COFF Header (после PE signature)
            int coffOffset = peOffset + 4;

            header.Machine = ReadUInt16Safe(data, coffOffset);
            header.NumberOfSections = ReadUInt16Safe(data, coffOffset + 2);
            header.TimeDateStamp = ReadUInt32Safe(data, coffOffset + 4);
            header.PointerToSymbolTable = ReadUInt32Safe(data, coffOffset + 8);
            header.NumberOfSymbols = ReadUInt32Safe(data, coffOffset + 12);
            header.SizeOfOptionalHeader = ReadUInt16Safe(data, coffOffset + 16);
            header.Characteristics = ReadUInt16Safe(data, coffOffset + 18);

            // Optional Header
            int optionalHeaderOffset = coffOffset + 20;
            if (optionalHeaderOffset + header.SizeOfOptionalHeader > data.Length)
                throw new InvalidDataException("Optional header extends beyond file size");

            header.Magic = ReadUInt16Safe(data, optionalHeaderOffset);
            header.Is64Bit = header.Magic == 0x20b;

            header.AddressOfEntryPoint = ReadUInt32Safe(data, optionalHeaderOffset + 16);
            header.ImageBase = header.Is64Bit
                ? ReadUInt64Safe(data, optionalHeaderOffset + 24)
                : ReadUInt32Safe(data, optionalHeaderOffset + 28);

            header.SectionAlignment = ReadUInt32Safe(data, optionalHeaderOffset + 32);
            header.FileAlignment = ReadUInt32Safe(data, optionalHeaderOffset + 36);

            int dataDirectoryOffset = header.Is64Bit
                ? optionalHeaderOffset + 112
                : optionalHeaderOffset + 96;

            if (dataDirectoryOffset + 16 > data.Length)
                throw new InvalidDataException("Data directories extend beyond file size");

            // Import Directory
            header.ImportDirectoryRVA = ReadUInt32Safe(data, dataDirectoryOffset + 8);
            header.ImportDirectorySize = ReadUInt32Safe(data, dataDirectoryOffset + 12);

            // Export Directory
            header.ExportDirectoryRVA = ReadUInt32Safe(data, dataDirectoryOffset);
            header.ExportDirectorySize = ReadUInt32Safe(data, dataDirectoryOffset + 4);

            return header;
        }

        public string GetHeaders()
        {
            if (peHeader == null)
                return "PE file not loaded";

            var sb = new StringBuilder();
            sb.AppendLine("═══════════════════════════════════════════════════════════");
            sb.AppendLine("                    PE HEADER ANALYSIS");
            sb.AppendLine("═══════════════════════════════════════════════════════════");
            sb.AppendLine();

            sb.AppendLine("📋 BASIC INFORMATION:");
            sb.AppendLine($"  File:              {Path.GetFileName(filePath)}");
            sb.AppendLine($"  Size:              {fileData?.Length:N0} bytes");
            sb.AppendLine($"  Architecture:      {(peHeader.Is64Bit ? "x64 (64-bit)" : "x86 (32-bit)")}");
            sb.AppendLine($"  Machine Type:      0x{peHeader.Machine:X4} ({GetMachineType(peHeader.Machine)})");
            sb.AppendLine();

            sb.AppendLine("🔧 COFF HEADER:");
            sb.AppendLine($"  PE Offset:         0x{peHeader.PEOffset:X8}");
            sb.AppendLine($"  Sections:          {peHeader.NumberOfSections}");
            sb.AppendLine($"  Timestamp:         {DateTimeOffset.FromUnixTimeSeconds(peHeader.TimeDateStamp).DateTime}");
            sb.AppendLine($"  Symbol Table:      0x{peHeader.PointerToSymbolTable:X8}");
            sb.AppendLine($"  Symbols:           {peHeader.NumberOfSymbols}");
            sb.AppendLine($"  Optional Header:   {peHeader.SizeOfOptionalHeader} bytes");
            sb.AppendLine($"  Characteristics:   0x{peHeader.Characteristics:X4}");
            sb.AppendLine($"    {GetCharacteristics(peHeader.Characteristics)}");
            sb.AppendLine();

            sb.AppendLine("⚙️ OPTIONAL HEADER:");
            sb.AppendLine($"  Magic:             0x{peHeader.Magic:X4}");
            sb.AppendLine($"  Entry Point:       0x{peHeader.AddressOfEntryPoint:X8}");
            sb.AppendLine($"  Image Base:        0x{peHeader.ImageBase:X}");
            sb.AppendLine($"  Section Align:     0x{peHeader.SectionAlignment:X8}");
            sb.AppendLine($"  File Align:        0x{peHeader.FileAlignment:X8}");
            sb.AppendLine();

            sb.AppendLine("📁 DATA DIRECTORIES:");
            sb.AppendLine($"  Import Dir RVA:    0x{peHeader.ImportDirectoryRVA:X8}");
            sb.AppendLine($"  Import Dir Size:   {peHeader.ImportDirectorySize} bytes");
            sb.AppendLine($"  Export Dir RVA:    0x{peHeader.ExportDirectoryRVA:X8}");
            sb.AppendLine($"  Export Dir Size:   {peHeader.ExportDirectorySize} bytes");
            sb.AppendLine();

            return sb.ToString();
        }

        public List<PESection> GetSections()
        {
            if (fileData == null || peHeader == null)
                return new List<PESection>();

            var sections = new List<PESection>();
            int sectionHeaderOffset = peHeader.PEOffset + 24 + peHeader.SizeOfOptionalHeader;

            for (int i = 0; i < peHeader.NumberOfSections; i++)
            {
                int offset = sectionHeaderOffset + (i * 40);
                if (offset + 40 > fileData.Length)
                    break; // corrupted or truncated

                var section = new PESection
                {
                    Name = Encoding.ASCII.GetString(fileData, offset, 8).TrimEnd('\0'),
                    VirtualSize = ReadUInt32Safe(fileData, offset + 8),
                    VirtualAddress = $"0x{ReadUInt32Safe(fileData, offset + 12):X8}",
                    RawSize = ReadUInt32Safe(fileData, offset + 16),
                    RawPointer = ReadUInt32Safe(fileData, offset + 20),
                    Characteristics = GetSectionCharacteristics(ReadUInt32Safe(fileData, offset + 36))
                };

                sections.Add(section);
            }

            return sections;
        }

        public List<PEImport> GetImports()
        {
            if (fileData == null || peHeader == null || peHeader.ImportDirectoryRVA == 0)
                return new List<PEImport>();

            var imports = new List<PEImport>();

            try
            {
                int importOffset = RVAToFileOffset(peHeader.ImportDirectoryRVA);
                if (importOffset <= 0 || importOffset >= fileData.Length)
                    return imports;

                while (importOffset + 20 <= fileData.Length)
                {
                    uint nameRVA = ReadUInt32Safe(fileData, importOffset + 12);
                    if (nameRVA == 0) break;

                    uint thunkRVA = ReadUInt32Safe(fileData, importOffset);
                    int dllNameOffset = RVAToFileOffset(nameRVA);
                    if (dllNameOffset < 0 || dllNameOffset >= fileData.Length) break;

                    string dllName = ReadNullTerminatedString(fileData, dllNameOffset);

                    // Read import functions
                    int thunkOffset = RVAToFileOffset(thunkRVA);
                    if (thunkOffset < 0 || thunkOffset >= fileData.Length) break;

                    while (thunkOffset + (peHeader.Is64Bit ? 8 : 4) <= fileData.Length)
                    {
                        ulong thunkValue = peHeader.Is64Bit
                            ? ReadUInt64Safe(fileData, thunkOffset)
                            : ReadUInt32Safe(fileData, thunkOffset);

                        if (thunkValue == 0) break;

                        string functionName;

                        // Check if import by ordinal
                        if ((peHeader.Is64Bit && (thunkValue & 0x8000000000000000) != 0) ||
                            (!peHeader.Is64Bit && (thunkValue & 0x80000000) != 0))
                        {
                            ushort ordinal = (ushort)(thunkValue & 0xFFFF);
                            functionName = $"Ordinal_{ordinal}";
                        }
                        else
                        {
                            uint nameRVAFunc = (uint)(thunkValue & 0x7FFFFFFF);
                            int funcNameOffset = RVAToFileOffset(nameRVAFunc) + 2; // skip hint
                            if (funcNameOffset < 0 || funcNameOffset >= fileData.Length) break;
                            functionName = ReadNullTerminatedString(fileData, funcNameOffset);
                        }

                        imports.Add(new PEImport
                        {
                            DllName = dllName,
                            FunctionName = functionName,
                            Address = $"0x{thunkValue:X}"
                        });

                        thunkOffset += peHeader.Is64Bit ? 8 : 4;
                    }

                    importOffset += 20;
                }
            }
            catch
            {
                // Import parsing failed - return what we have
            }

            return imports;
        }

        public List<PEExport> GetExports()
        {
            if (fileData == null || peHeader == null || peHeader.ExportDirectoryRVA == 0)
                return new List<PEExport>();

            var exports = new List<PEExport>();

            try
            {
                int exportOffset = RVAToFileOffset(peHeader.ExportDirectoryRVA);
                if (exportOffset <= 0 || exportOffset + 40 > fileData.Length)
                    return exports;

                uint numberOfFunctions = ReadUInt32Safe(fileData, exportOffset + 20);
                uint numberOfNames = ReadUInt32Safe(fileData, exportOffset + 24);
                uint addressTableRVA = ReadUInt32Safe(fileData, exportOffset + 28);
                uint nameTableRVA = ReadUInt32Safe(fileData, exportOffset + 32);
                uint ordinalTableRVA = ReadUInt32Safe(fileData, exportOffset + 36);

                int addressTableOffset = RVAToFileOffset(addressTableRVA);
                int nameTableOffset = RVAToFileOffset(nameTableRVA);
                int ordinalTableOffset = RVAToFileOffset(ordinalTableRVA);

                if (addressTableOffset < 0 || nameTableOffset < 0 || ordinalTableOffset < 0)
                    return exports;

                for (int i = 0; i < numberOfNames; i++)
                {
                    int nameRVAOffset = nameTableOffset + (i * 4);
                    if (nameRVAOffset + 4 > fileData.Length) break;

                    uint nameRVA = ReadUInt32Safe(fileData, nameRVAOffset);
                    int ordinalOffset = ordinalTableOffset + (i * 2);
                    if (ordinalOffset + 2 > fileData.Length) break;

                    ushort ordinal = ReadUInt16Safe(fileData, ordinalOffset);

                    int addressOffset = addressTableOffset + (ordinal * 4);
                    if (addressOffset + 4 > fileData.Length) break;

                    uint functionRVA = ReadUInt32Safe(fileData, addressOffset);

                    int nameOffset = RVAToFileOffset(nameRVA);
                    if (nameOffset < 0 || nameOffset >= fileData.Length) continue;

                    string functionName = ReadNullTerminatedString(fileData, nameOffset);

                    exports.Add(new PEExport
                    {
                        FunctionName = functionName,
                        Ordinal = ordinal,
                        Rva = $"0x{functionRVA:X8}"
                    });
                }
            }
            catch
            {
                // Export parsing failed
            }

            return exports;
        }

        private int RVAToFileOffset(uint rva)
        {
            if (peHeader == null || fileData == null)
                return -1;

            int sectionHeaderOffset = peHeader.PEOffset + 24 + peHeader.SizeOfOptionalHeader;
            if (sectionHeaderOffset < 0 || sectionHeaderOffset >= fileData.Length)
                return -1;

            for (int i = 0; i < peHeader.NumberOfSections; i++)
            {
                int offset = sectionHeaderOffset + (i * 40);
                if (offset + 40 > fileData.Length) break;

                uint virtualAddress = ReadUInt32Safe(fileData, offset + 12);
                uint virtualSize = ReadUInt32Safe(fileData, offset + 8);
                uint rawPointer = ReadUInt32Safe(fileData, offset + 20);

                if (rva >= virtualAddress && rva < virtualAddress + virtualSize)
                {
                    long calc = (long)rva - virtualAddress + rawPointer;
                    if (calc < 0 || calc > int.MaxValue || calc >= fileData.Length) return -1;
                    return (int)calc;
                }
            }

            // If not found in sections, return rva as fallback if within file
            if (rva < fileData.Length)
                return (int)rva;

            return -1;
        }

        private string ReadNullTerminatedString(byte[] data, int offset)
        {
            if (offset < 0 || offset >= data.Length)
                return string.Empty;

            int length = 0;
            while (offset + length < data.Length && data[offset + length] != 0)
            {
                length++;
            }

            return Encoding.ASCII.GetString(data, offset, length);
        }

        private string GetMachineType(ushort machine)
        {
            return machine switch
            {
                0x014c => "Intel 386 (x86)",
                0x8664 => "AMD64 (x64)",
                0x0162 => "MIPS R3000",
                0x01a2 => "Hitachi SH3",
                0x01c0 => "ARM",
                0xaa64 => "ARM64",
                0x0200 => "Intel Itanium",
                _ => "Unknown"
            };
        }

        private string GetCharacteristics(ushort characteristics)
        {
            var flags = new List<string>();
            if ((characteristics & 0x0001) != 0) flags.Add("RELOCS_STRIPPED");
            if ((characteristics & 0x0002) != 0) flags.Add("EXECUTABLE_IMAGE");
            if ((characteristics & 0x0004) != 0) flags.Add("LINE_NUMS_STRIPPED");
            if ((characteristics & 0x0008) != 0) flags.Add("LOCAL_SYMS_STRIPPED");
            if ((characteristics & 0x0020) != 0) flags.Add("LARGE_ADDRESS_AWARE");
            if ((characteristics & 0x0100) != 0) flags.Add("32BIT_MACHINE");
            if ((characteristics & 0x0200) != 0) flags.Add("DEBUG_STRIPPED");
            if ((characteristics & 0x1000) != 0) flags.Add("SYSTEM");
            if ((characteristics & 0x2000) != 0) flags.Add("DLL");

            return string.Join(", ", flags);
        }

        private string GetSectionCharacteristics(uint characteristics)
        {
            var flags = new List<string>();
            if ((characteristics & 0x00000020) != 0) flags.Add("CODE");
            if ((characteristics & 0x00000040) != 0) flags.Add("INITIALIZED_DATA");
            if ((characteristics & 0x00000080) != 0) flags.Add("UNINITIALIZED_DATA");
            if ((characteristics & 0x02000000) != 0) flags.Add("DISCARDABLE");
            if ((characteristics & 0x10000000) != 0) flags.Add("SHARED");
            if ((characteristics & 0x20000000) != 0) flags.Add("EXECUTE");
            if ((characteristics & 0x40000000) != 0) flags.Add("READ");
            if ((characteristics & 0x80000000) != 0) flags.Add("WRITE");

            return string.Join(" | ", flags);
        }

        public void ExportAnalysis(string outputPath)
        {
            var sb = new StringBuilder();

            sb.AppendLine("════════════════════════════════════════════════════════");
            sb.AppendLine("           PE ANALYSIS REPORT");
            sb.AppendLine("════════════════════════════════════════════════════════");
            sb.AppendLine();
            sb.AppendLine(GetHeaders());
            sb.AppendLine();

            sb.AppendLine("════════════════════════════════════════════════════════");
            sb.AppendLine("                    SECTIONS");
            sb.AppendLine("════════════════════════════════════════════════════════");
            foreach (var section in GetSections())
            {
                sb.AppendLine($"Section: {section.Name}");
                sb.AppendLine($"  Virtual Address: {section.VirtualAddress}");
                sb.AppendLine($"  Virtual Size:    {section.VirtualSize:N0} байт");
                sb.AppendLine($"  Raw Size:        {section.RawSize:N0} байт");
                sb.AppendLine($"  Characteristics: {section.Characteristics}");
                sb.AppendLine();
            }

            sb.AppendLine("════════════════════════════════════════════════════════");
            sb.AppendLine("                    IMPORTS");
            sb.AppendLine("════════════════════════════════════════════════════════");
            var imports = GetImports().GroupBy(i => i.DllName);
            foreach (var dll in imports)
            {
                sb.AppendLine($"\n{dll.Key}:");
                foreach (var func in dll)
                {
                    sb.AppendLine($"  - {func.FunctionName}");
                }
            }

            sb.AppendLine("\n═══════════════════════════════════════════════════════");
            sb.AppendLine("                    EXPORTS");
            sb.AppendLine("════════════════════════════════════════════════════════");
            foreach (var export in GetExports())
            {
                sb.AppendLine($"  {export.FunctionName} (Ordinal: {export.Ordinal}, RVA: {export.Rva})");
            }

            File.WriteAllText(outputPath, sb.ToString());
        }
    }

    public class PEHeader
    {
        public int PEOffset { get; set; }
        public ushort Machine { get; set; }
        public ushort NumberOfSections { get; set; }
        public uint TimeDateStamp { get; set; }
        public uint PointerToSymbolTable { get; set; }
        public uint NumberOfSymbols { get; set; }
        public ushort SizeOfOptionalHeader { get; set; }
        public ushort Characteristics { get; set; }
        public ushort Magic { get; set; }
        public bool Is64Bit { get; set; }
        public uint AddressOfEntryPoint { get; set; }
        public ulong ImageBase { get; set; }
        public uint SectionAlignment { get; set; }
        public uint FileAlignment { get; set; }
        public uint ImportDirectoryRVA { get; set; }
        public uint ImportDirectorySize { get; set; }
        public uint ExportDirectoryRVA { get; set; }
        public uint ExportDirectorySize { get; set; }
    }

    public class PESection
    {
        public string Name { get; set; } = string.Empty;
        public uint VirtualSize { get; set; }
        public string VirtualAddress { get; set; } = string.Empty;
        public uint RawSize { get; set; }
        public uint RawPointer { get; set; }
        public string Characteristics { get; set; } = string.Empty;
    }

    public class PEImport
    {
        public string DllName { get; set; } = string.Empty;
        public string FunctionName { get; set; } = string.Empty;
        public string Address { get; set; } = string.Empty;
    }

    public class PEExport
    {
        public string FunctionName { get; set; } = string.Empty;
        public ushort Ordinal { get; set; }
        public string Rva { get; set; } = string.Empty;
    }
}
