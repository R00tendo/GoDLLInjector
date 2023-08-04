// DLL Injector
package main

import (
	"errors"
	"flag"
	"log"
	"os"
	"syscall"

	clog "github.com/charmbracelet/log"
	ps "github.com/mitchellh/go-ps"
	"golang.org/x/sys/windows"
)

func main() {
	var dPath string
	var _pId int
	var pName string
	flag.StringVar(&pName, "process", "", "Process name to inject to")
	flag.StringVar(&dPath, "dll", "", "DLL to inject")
	flag.Parse()
	pList, err := ps.Processes()
	for pI := range pList {
		process := pList[pI]
		if process.Executable() == pName {
			_pId = process.Pid()
			break
		}
	}
	if _pId == 0 {
		log.Fatal("Process not found")
	}
	pId := uintptr(_pId)
	if _, err := os.Stat(dPath); errors.Is(err, os.ErrNotExist) {
		log.Fatal(err)
	}

	kernel32 := windows.NewLazyDLL("kernel32.dll")
	pHandle, err := windows.OpenProcess(windows.PROCESS_CREATE_THREAD|windows.PROCESS_VM_OPERATION|windows.PROCESS_VM_WRITE|windows.PROCESS_VM_READ|windows.PROCESS_QUERY_INFORMATION, false, uint32(pId))
	if err != nil {
		log.Fatal(err)
	}
	clog.Info("Process opened")

	VirtualAllocEx := kernel32.NewProc("VirtualAllocEx")
	vAlloc, _, err := VirtualAllocEx.Call(uintptr(pHandle), 0, uintptr(len(dPath)+1), windows.MEM_RESERVE|windows.MEM_COMMIT, windows.PAGE_EXECUTE_READWRITE)
	clog.Info("Memory allocated")

	bPtrDpath, err := windows.BytePtrFromString(dPath)
	if err != nil {
		log.Fatal(err)
	}

	Zero := uintptr(0)
	err = windows.WriteProcessMemory(pHandle, vAlloc, bPtrDpath, uintptr(len(dPath)+1), &Zero)
	if err != nil {
		log.Fatal(err)
	}
	clog.Info("Memory written")

	LoadLibAddy, err := syscall.GetProcAddress(syscall.Handle(kernel32.Handle()), "LoadLibraryA")
	if err != nil {
		log.Fatal(err)
	}

	tHandle, _, err := kernel32.NewProc("CreateRemoteThread").Call(uintptr(pHandle), 0, 0, LoadLibAddy, vAlloc, 0, 0)
	defer syscall.CloseHandle(syscall.Handle(tHandle))
	clog.Info("Thread created")
	clog.Info("DLL injected successfully!")
}
