// dlluminator_simple.cpp
// C++17: scan a single DLL/PE or a directory for PE files and report the specified section's Virtual Size in KB.
// Usage:
//   ./dlluminator_simple --dll <path> [--section <name>] [--min-size-kb N] [--csv <file>]
//   OR
//   ./dlluminator_simple --directory <dir> [--section <name>] [--min-size-kb N] [--csv <file>]

#include <iostream>
#include <fstream>
#include <iomanip>
#include <vector>
#include <string>
#include <algorithm>
#include <filesystem>
#include <cstdint>
#include <cstring>

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

struct Entry {
    std::string path;
    std::string filename;
    double virtual_kb;
};

// parse section virtual size (PE32/PE32+ compatible since section headers are same). returns true on success and fills virtualSize
bool parse_section_virtual_size(const std::string& filepath, const std::string& section_name, uint32_t& virtualSize) {
    std::ifstream f(filepath, std::ios::binary);
    if (!f) return false;

    IMAGE_DOS_HEADER dos;
    f.read(reinterpret_cast<char*>(&dos), sizeof(dos));
    if (!f || dos.e_magic != 0x5A4D) return false; // not a DOS MZ

    // Move to NT headers
    f.seekg(dos.e_lfanew, std::ios::beg);
    uint32_t pe_sig = 0;
    IMAGE_FILE_HEADER fileHeader;
    f.read(reinterpret_cast<char*>(&pe_sig), sizeof(pe_sig));
    f.read(reinterpret_cast<char*>(&fileHeader), sizeof(fileHeader));
    if (!f || pe_sig != 0x00004550) return false; // not a PE

    // Seek to section headers (skip optional header)
    std::streamoff sectionHeadersStart = (std::streamoff)dos.e_lfanew + sizeof(uint32_t) + sizeof(IMAGE_FILE_HEADER) + fileHeader.SizeOfOptionalHeader;
    f.seekg(sectionHeadersStart, std::ios::beg);
    if (!f) return false;

    uint16_t nSections = fileHeader.NumberOfSections;
    for (uint16_t i = 0; i < nSections; ++i) {
        IMAGE_SECTION_HEADER sh;
        f.read(reinterpret_cast<char*>(&sh), sizeof(sh));
        if (!f) return false;
        char namebuf[9] = { 0 };
        std::memcpy(namebuf, sh.Name, 8);
        if (section_name == std::string(namebuf)) {
            virtualSize = sh.Misc.VirtualSize;
            return true;
        }
    }
    return false;
}

static std::string to_lower(std::string s) {
    for (auto& c : s) c = (char)std::tolower((unsigned char)c);
    return s;
}

void print_usage(const char* prog) {
    std::cerr << "Usage:\n"
        << "  " << prog << " --dll <path> [--section <name>] [--min-size-kb N] [--csv <file>]\n"
        << "  " << prog << " --directory <dir> [--section <name>] [--min-size-kb N] [--csv <file>]\n\n"
        << "Defaults: section = .text, min-size-kb = 0\n";
}

int main(int argc, char** argv) {
    if (argc < 3) {
        print_usage(argv[0]);
        return 1;
    }

    std::string mode_dll, mode_dir;
    std::string section = ".text";
    double min_size_kb = 0.0;
    std::string csv_out;

    // simple arg parsing
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--dll") {
            if (i + 1 >= argc) { print_usage(argv[0]); return 1; }
            mode_dll = argv[++i];
        }
        else if (a == "--directory") {
            if (i + 1 >= argc) { print_usage(argv[0]); return 1; }
            mode_dir = argv[++i];
        }
        else if (a == "--section") {
            if (i + 1 >= argc) { print_usage(argv[0]); return 1; }
            section = argv[++i];
        }
        else if (a == "--min-size-kb") {
            if (i + 1 >= argc) { print_usage(argv[0]); return 1; }
            try { min_size_kb = std::stod(argv[++i]); }
            catch (...) { min_size_kb = 0.0; }
        }
        else if (a == "--csv") {
            if (i + 1 >= argc) { print_usage(argv[0]); return 1; }
            csv_out = argv[++i];
        }
        else {
            print_usage(argv[0]);
            return 1;
        }
    }

    if (mode_dll.empty() == mode_dir.empty()) {
        std::cerr << "Provide exactly one of --dll or --directory.\n";
        print_usage(argv[0]);
        return 1;
    }

    std::vector<Entry> results;

    // helper to process a single file
    auto process_file = [&](const fs::path& p) {
        if (!fs::is_regular_file(p)) return;
        // quick extension filter for common PE types
        std::string ext = to_lower(p.extension().string());
        if (!ext.empty()) {
            if (ext != ".dll" && ext != ".exe" && ext != ".sys") {
                // skip non-PE in directory mode
                return;
            }
        }
        uint32_t vsize = 0;
        if (!parse_section_virtual_size(p.string(), section, vsize)) return;
        double vkb = vsize / 1024.0;
        if (vkb < min_size_kb) return;
        results.push_back({ p.string(), p.filename().string(), vkb });
        };

    try {
        if (!mode_dll.empty()) {
            fs::path p(mode_dll);
            process_file(p);
        }
        else {
            fs::path dir(mode_dir);
            if (!fs::exists(dir) || !fs::is_directory(dir)) {
                std::cerr << "Invalid directory: " << dir << "\n";
                return 1;
            }
            for (const auto& entry : fs::directory_iterator(dir)) {
                process_file(entry.path());
            }
        }
    }
    catch (const std::exception& e) {
        std::cerr << "Error during iteration: " << e.what() << "\n";
        return 1;
    }

    // sort by size descending (single source of truth)
    std::sort(results.begin(), results.end(), [](const Entry& a, const Entry& b) {
        return a.virtual_kb > b.virtual_kb;
        });

    // print results (table)
    std::cout << std::fixed << std::setprecision(2);
    std::cout << "Section: " << section << "\n";
    if (!mode_dll.empty()) std::cout << "Scanned file: " << mode_dll << "\n";
    else std::cout << "Scanned directory: " << mode_dir << "\n";
    std::cout << "\n" << std::left << std::setw(60) << "File" << " | " << "Text Section Size (KB)\n";
    std::cout << std::string(85, '-') << "\n";
    for (const auto& e : results) {
        std::cout << std::left << std::setw(60) << e.filename << " | " << e.virtual_kb << " KB\n";
    }
    if (results.empty()) std::cout << "No files matched the criteria.\n";

  

    // Write CSV if requested (same sorted order)
    if (!csv_out.empty()) {
        std::ofstream csv(csv_out);
        if (!csv) {
            std::cerr << "Failed to open CSV file: " << csv_out << "\n";
            return 1;
        }
        csv << "file,virtual_kb\n";
        for (const auto& e : results) {
            csv << std::quoted(e.path) << ',' << e.virtual_kb << '\n';
        }
        std::cout << "\nCSV exported to: " << csv_out << "\n";
    }

    return 0;
}
