#include <iostream>
#include <fstream>
#include <iomanip>
#include <cstring>
#include <cstdint>
#include <filesystem>
#include <vector>
#include <algorithm>

namespace fs = std::filesystem;

#pragma pack(push,1)
struct IMAGE_DOS_HEADER {
    uint16_t e_magic;
    uint16_t e_cblp;
    uint16_t e_cp;
    uint16_t e_crlc;
    uint16_t e_cparhdr;
    uint16_t e_minalloc;
    uint16_t e_maxalloc;
    uint16_t e_ss;
    uint16_t e_sp;
    uint16_t e_csum;
    uint16_t e_ip;
    uint16_t e_cs;
    uint16_t e_lfarlc;
    uint16_t e_ovno;
    uint16_t e_res[4];
    uint16_t e_oemid;
    uint16_t e_oeminfo;
    uint16_t e_res2[10];
    int32_t  e_lfanew;
};

struct IMAGE_FILE_HEADER {
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
};

struct IMAGE_DATA_DIRECTORY {
    uint32_t VirtualAddress;
    uint32_t Size;
};

struct IMAGE_OPTIONAL_HEADER32 {
    uint16_t Magic;
    uint8_t  MajorLinkerVersion;
    uint8_t  MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
    uint32_t BaseOfData;
    uint32_t ImageBase;
    uint32_t SectionAlignment;
    uint32_t FileAlignment;
    uint16_t MajorOperatingSystemVersion;
    uint16_t MinorOperatingSystemVersion;
    uint16_t MajorImageVersion;
    uint16_t MinorImageVersion;
    uint16_t MajorSubsystemVersion;
    uint16_t MinorSubsystemVersion;
    uint32_t Win32VersionValue;
    uint32_t SizeOfImage;
    uint32_t SizeOfHeaders;
    uint32_t CheckSum;
    uint16_t Subsystem;
    uint16_t DllCharacteristics;
    uint32_t SizeOfStackReserve;
    uint32_t SizeOfStackCommit;
    uint32_t SizeOfHeapReserve;
    uint32_t SizeOfHeapCommit;
    uint32_t LoaderFlags;
    uint32_t NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[16];
};

struct IMAGE_NT_HEADERS32 {
    uint32_t Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER32 OptionalHeader;
};

struct IMAGE_SECTION_HEADER {
    char     Name[8];
    union {
        uint32_t PhysicalAddress;
        uint32_t VirtualSize;
    } Misc;
    uint32_t VirtualAddress;
    uint32_t SizeOfRawData;
    uint32_t PointerToRawData;
    uint32_t PointerToRelocations;
    uint32_t PointerToLinenumbers;
    uint16_t NumberOfRelocations;
    uint16_t NumberOfLinenumbers;
    uint32_t Characteristics;
};
#pragma pack(pop)

double get_text_section_size_kb(const std::string& filepath) {
    std::ifstream f(filepath, std::ios::binary);
    if (!f) return -1.0;

    IMAGE_DOS_HEADER dosHdr;
    f.read(reinterpret_cast<char*>(&dosHdr), sizeof(dosHdr));
    if (dosHdr.e_magic != 0x5A4D) return -1.0;

    f.seekg(dosHdr.e_lfanew, std::ios::beg);
    IMAGE_NT_HEADERS32 ntHdr;
    f.read(reinterpret_cast<char*>(&ntHdr), sizeof(ntHdr));
    if (ntHdr.Signature != 0x00004550) return -1.0;

    uint16_t numSections = ntHdr.FileHeader.NumberOfSections;
    size_t sectionHeadersStart = dosHdr.e_lfanew + sizeof(uint32_t) + sizeof(IMAGE_FILE_HEADER)
        + ntHdr.FileHeader.SizeOfOptionalHeader;
    f.seekg(sectionHeadersStart, std::ios::beg);

    for (uint16_t i = 0; i < numSections; i++) {
        IMAGE_SECTION_HEADER secHdr;
        f.read(reinterpret_cast<char*>(&secHdr), sizeof(secHdr));
        char name[9] = { 0 };
        memcpy(name, secHdr.Name, 8);

        if (strcmp(name, ".text") == 0) {
            return secHdr.Misc.VirtualSize / 1024.0; // KB
        }
    }
    return -1.0;
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <directory_path>\n";
        return 1;
    }

    fs::path dirPath(argv[1]);
    if (!fs::exists(dirPath) || !fs::is_directory(dirPath)) {
        std::cerr << "Invalid directory path: " << dirPath << "\n";
        return 1;
    }

    struct Entry {
        std::string name;
        double sizeKB;
    };
    std::vector<Entry> results;

    for (const auto& entry : fs::directory_iterator(dirPath)) {
        if (!entry.is_regular_file()) continue;
        auto ext = entry.path().extension().string();
        if (ext == ".dll") {
            double sizeKB = get_text_section_size_kb(entry.path().string());
            if (sizeKB > 0) {
                results.push_back({ entry.path().filename().string(), sizeKB });
            }
        }
    }

    // Sort by size (descending)
    std::sort(results.begin(), results.end(), [](const Entry& a, const Entry& b) {
        return a.sizeKB > b.sizeKB;
        });

    std::cout << std::fixed << std::setprecision(2);
    std::cout << "\nScanning directory: " << dirPath << "\n";
    std::cout << std::left << std::setw(50) << "File" << " | " << "Text Section Size (KB)\n";
    std::cout << std::string(75, '-') << "\n";

    for (const auto& e : results) {
        std::cout << std::left << std::setw(50) << e.name << " | " << e.sizeKB << " KB\n";
    }

    if (results.empty())
        std::cout << "No valid PE files found.\n";

    return 0;
}
