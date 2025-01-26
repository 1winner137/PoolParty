# PoolParty Fork

This repository is a fork of the original [PoolParty project by SafeBreach-Labs](https://github.com/SafeBreach-Labs/PoolParty).

## About

PoolParty is a Windows tool designed to demonstrate process hollowing techniques. This fork includes minor updates to enhance functionality and usability.

## Updates in This Fork

- **Added Support for Custom Path Input:**  
  Updated the executable to accept a new argument:
  ```
  PoolParty.exe -V 8 -P 1234 -path C:\Users\User\Download\program.exe
  ```
  The `-path` argument allows specifying the full path to the program you wish to execute.

## Usage

```
PoolParty.exe -V <version> -P <process_id> -path <program_path>
```

### Arguments
- `-V`: Version parameter (integer, e.g., `8`).
- `-P`: Process ID (integer, e.g., `1234`).
- `-path`: Full path to the executable file (e.g., `C:\Users\User\Download\program.exe`).

## Original Repository

The original PoolParty repository by SafeBreach-Labs can be found [here](https://github.com/SafeBreach-Labs/PoolParty).

---
This are retained from original project
# PoolParty
A collection of fully-undetectable process injection techniques abusing Windows Thread Pools. Presented at Black Hat EU 2023 Briefings under the title - [**The Pool Party You Will Never Forget: New Process Injection Techniques Using Windows Thread Pools**](https://www.blackhat.com/eu-23/briefings/schedule/#the-pool-party-you-will-never-forget-new-process-injection-techniques-using-windows-thread-pools-35446)

## PoolParty Variants

| Variant ID  | Varient Description |
| ------------- | ----------------- |
| 1  | Overwrite the start routine of the target worker factory       |
| 2  | Insert TP_WORK work item to the target process's thread pool   |
| 3  | Insert TP_WAIT work item to the target process's thread pool   |
| 4  | Insert TP_IO work item to the target process's thread pool     |
| 5  | Insert TP_ALPC work item to the target process's thread pool   |
| 6  | Insert TP_JOB work item to the target process's thread pool    |
| 7  | Insert TP_DIRECT work item to the target process's thread pool |
| 8  | Insert TP_TIMER work item to the target process's thread pool  |

## Usage
```
PoolParty.exe -V <VARIANT ID> -P <TARGET PID> -path <ABSOLUTE PATH TO PROGRAM TO EXECUTE>
```

## Usage Examples

Insert TP_TIMER work item to process ID 1234
```
>> PoolParty.exe -V 8 -P 1234 -path C:\Users\User\Download\program.exe

[info]    Starting PoolParty attack against process id: 1234
[info]    Retrieved handle to the target process: 00000000000000B8
[info]    Hijacked worker factory handle from the target process: 0000000000000058
[info]    Hijacked timer queue handle from the target process: 0000000000000054
[info]    Allocated shellcode memory in the target process: 00000281DBEF0000
[info]    Written shellcode to the target process
[info]    Retrieved target worker factory basic information
[info]    Created TP_TIMER structure associated with the shellcode
[info]    Allocated TP_TIMER memory in the target process: 00000281DBF00000
[info]    Written the specially crafted TP_TIMER structure to the target process
[info]    Modified the target process's TP_POOL tiemr queue list entry to point to the specially crafted TP_TIMER
[info]    Set the timer queue to expire to trigger the dequeueing TppTimerQueueExpiration
[info]    PoolParty attack completed successfully

```

## Default Shellcode and Customization
The default shellcode spawns a calculator via the [WinExec API](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-winexec). 

To customize the executable to execute, change the path in the end of the `g_Shellcode` variable present in the main.cpp file.

## Author - Alon Leviev
* LinkedIn - [Alon Leviev](https://il.linkedin.com/in/alonleviev)
* Twitter - [@_0xDeku](https://twitter.com/_0xDeku)
