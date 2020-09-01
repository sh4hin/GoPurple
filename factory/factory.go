package factory

import (
	"github.com/sh4hin/GoPurple/techniques"
	"fmt"
)

func Run(tech string, url string, pid int, prog string, args string, block string) {
    switch tech {
	case "1":
		techniques.RunFiber(url)
	case "2":
		techniques.RunSyscall(url)
	case "3":
		techniques.RunCreateThreadNative(url)
	case "4":
		techniques.RunCreateProcess(url, prog, args)
	case "5":
		techniques.RunEtwpCreateEtwThread(url)
	case "6":
		techniques.RunCreateRemoteThread(url, pid)
	case "7":
		techniques.RunRtlCreateUserThread(url, pid)
	case "8":
		techniques.RunCreateThread(url)
	case "9":
		techniques.RunCreateRemoteThreadNative(url, pid)
	case "10":
		techniques.RunCreateProcessWithPipe(url, prog, args)
	case "11":
		techniques.RunQueueUserAPC(url, pid ,prog, block)
	case "12":
		techniques.RunCreateThreadpoolWait(url)
	case "13":
		techniques.RunBananaPhone(url)
	default:
		fmt.Printf("The following technique is invalid: %s.\n", tech)
	}
}

