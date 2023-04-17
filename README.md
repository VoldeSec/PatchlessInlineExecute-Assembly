# PatchlessInlineExecute-Assembly
Porting of BOF InlineExecute-Assembly to load .NET assembly in process but with **patchless AMSI and ETW bypass using hardware breakpoint**.

Using hardware breakpoints for patchless bypass has multiple advantages over traditional patching techniques. Firstly, it avoids using widely-known APIs such as NtProtectVirtualMemory, which are closely monitored by security solutions. Secondly, hardware breakpoints do not require any modification to the files/memory, which could be  detected by file integrity monitoring or EDR, resulting in a relatively stealthy approach.

Additionally, I have also rewritten the code to a standalone loader for wider usage: https://github.com/VoldeSec/PatchlessCLRLoader

# Compile
Run the below command inside the src directory via x64 Native Tools Command Prompt
```texinfo
cl.exe /c PatchlessinlineExecute-Assembly.c /GS- /FoPacthlessinlineExecute-Assemblyx64.o
```
Then import the PatchlessinlineExecute-Assembly.cna script on Cobalt Strike.
# Usage
Same as InlineExecute-Assembly,
```texinfo
PatchlessinlineExecute-Assembly --dotnetassembly /opt/SharpCollection/Seatbelt.exe --amsi --etw --assemblyargs AntiVirus --mailslot
```


# Credits
@rad9800 implementation of patchless hook

InlineExecute-Assembly - <https://github.com/anthemtotheego/InlineExecute-Assembly>
