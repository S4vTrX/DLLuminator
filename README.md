# Overview
DLL Stomp Scanner helps security researchers and blue teams identify DLL files that make attractive targets for Module Stomping attacks based on their .text section size and characteristics. Large .text sections with ample empty space are prime candidates for shellcode injection.

## What is Module Stomping?
Module Stomping is a code injection technique that:

1. Injects shellcode directly into the .text section of legitimate DLLs
2. Uses image memory regions instead of private memory
3. Overwrites ("stomps") existing code with malicious payloads
