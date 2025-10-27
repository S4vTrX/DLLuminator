# 🧩 DLLuminator — Module Stomp Scanner

**DLLuminator** helps security researchers and red teamers identify DLL and PE files that make attractive targets for **Module Stomping** attacks.  
It scans `.dll`, `.exe`, and `.sys` files, reports the `.text` section sizes, and sorts results in descending order — optionally exporting them to CSV.



## 🚨 What Is Module Stomping?

**Module Stomping** is a stealthy code injection technique that:
1. Injects shellcode directly into the `.text` section of a legitimate DLL.
2. Uses **image memory regions** instead of private memory (making detection harder).
3. Overwrites ("stomps") existing code with malicious payloads.

Large `.text` sections with slack space are **ideal** for this attack vector, since they provide ample room for in-memory payload placement without expanding memory regions or creating new mappings.



## 🧠 Overview

**DLLuminator** parses Portable Executable (PE) headers to extract section headers and compute the virtual size of a chosen section (default: `.text`).  
It can operate on:
- A **single DLL/PE file** using `--dll`, or
- A **directory** of files using `--directory`.

Results are sorted by section size (descending), and can be exported to CSV for analysis.



## ⚙️ Usage

```bash
dlluminator_simple --dll <path> [--section <name>] [--min-size-kb N] [--csv <file>]
dlluminator_simple --directory <dir> [--section <name>] [--min-size-kb N] [--csv <file>]
```


| Option              | Description                                                       |
| ------------------- | ----------------------------------------------------------------- |
| `--dll <path>`      | Scan a single DLL or PE file.                                     |
| `--directory <dir>` | Scan all `.dll`, `.exe`, and `.sys` files in the given directory. |
| `--section <name>`  | Specify the section name to inspect (default: `.text`).           |
| `--min-size-kb <N>` | Minimum size (in KB) to include in results.                       |
| `--csv <file>`      | Export results to a CSV file.                                     |


🧩 Credits

PE parsing logic inspired by [0xRick's Pe Parser Blog](https://0xrick.github.io/win-internals/pe8)
Concept inspired by research on Module Stomping, DLL hollowing, and reflective code injection.
