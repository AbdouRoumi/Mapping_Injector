
# Mapping_Injector Private

<a href="https://git.io/typing-svg"><img src="https://readme-typing-svg.demolab.com?font=Fira+Code&pause=1000&width=435&lines=Mapping_Injector+Private;Windows+Injection+Techniques+v1.0;" alt="Typing SVG" /></a>

**Mapping_Injector Private** is a Windows-based tool that showcases two injection techniques: **Local Mapping Injection** and **Remote Injection**, both of which fall under MITRE ATT&CK ID [T1055](https://attack.mitre.org/techniques/T1055/) – a category for various process injection methods. This tool is intended for educational purposes, malware analysis, and penetration testing within controlled environments to explore how process injection can be performed on Windows.

---

## How it Works

**Mapping_Injector Private** supports the following techniques:

### 1. **Local Mapping Injection**
   - A local injection technique where the injector maps memory within its own process and then injects code into a specified process.
  
### 2. **Remote Injection**
   - A remote injection technique that targets an external process.
  
---

## Features

- **Local Mapping Injection**: Allocates memory within the injector's own process to execute code.
- **Remote Injection**: Allocates and injects code into a remote process and executes the injected payload using `CreateRemoteThread`.
- **Shellcode Execution**: Executes arbitrary shellcode within the local or remote process.
- **Memory Management**: Manages memory allocation securely and changes memory protection using functions like `Mapviewoffile` 
- **Debugging Support**: Adds process control via debugging mechanisms for better control over injected processes.

---

## Code Highlights
- **Shellcode Writing**: Injects shellcode with `WriteProcessMemory` in the case of remote injection.
- **Thread Creation**: Executes shellcode by creating a new thread in the target process using `CreateRemoteThread`.
- **Protection Change**: Modifies memory protection to `PAGE_EXECUTE_READWRITE` for safe code execution.

---

## Prerequisites

- **Windows**: The tool is built to run specifically in Windows environments.
- **C Compiler**: Requires a C compiler (e.g., MSVC) to compile the provided source code.
- **Admin Privileges**: Needs to be executed with administrative privileges to inject code into remote processes.
  
---

## Usage

### Clone the repository:
```bash
git clone https://github.com/yourusername/mapping_injector_private.git
```

### Compile the code:
```bash
cl /EHsc mapping_injector_private.c
```

### Run the compiled binary:
For **Local Mapping Injection**:
```bash
mapping_injector_private.exe --local
```

For **Remote Injection**, targeting a process (e.g., `notepad.exe`):
```bash
mapping_injector_private.exe --remote notepad.exe
```

Alternatively, use **Visual Studio** for compilation and testing.

---

## Techniques Overview

- **Local Mapping Injection**: Executes shellcode within the injector's process space by mapping memory and creating threads internally.
- **Remote Injection**: Injects shellcode into external processes, writes to the target process memory, and creates remote threads to execute code.

### MITRE ATT&CK Reference:
**T1055 - Process Injection**: These techniques allow attackers to run arbitrary code in the address space of another process, providing access to the victim process's memory, privileges, or resources.

---

## Disclaimer

This tool is for **educational and testing purposes** only. It should be used legally and ethically, within controlled environments. Unauthorized use can lead to serious legal issues. The author is not responsible for any misuse or damages.

---
