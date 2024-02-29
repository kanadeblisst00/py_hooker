import os
import time
import platform
import sys
import psutil
from threading import Event
from .winapi import *
import winreg
from module_hot_loading import monitor_dir


def DelayCreateRemoteThread(*args):
    CreateRemoteThread(*args)
    time.sleep(0.05)

def get_pid_by_name(process_name):
    '''通过进程名查找第一个进程PID'''
    is_64bit = "64" in platform.architecture()[0] 
    for process in psutil.process_iter(['pid', 'name']):
        if process.info['name'] == process_name:
            pid = process.info['pid']
            if is_64bit != IsProcess64Bit(pid):
                raise Exception("Python位数和查找进程的位数不符，请同时使用32位或64位!")
            return pid

def add_runas():
    exe_path = sys.executable
    # 判断当前运行的Python是否具有管理员权限，没有则申请
    if not windll.shell32.IsUserAnAdmin():
        windll.shell32.ShellExecuteW(None, "runas", exe_path, __file__, None, 1)
    reg_path = r"Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers"
    try:
        reg_key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, reg_path, access=winreg.KEY_SET_VALUE | winreg.KEY_READ)
    except FileNotFoundError:
        winreg.CreateKey(winreg.HKEY_CURRENT_USER, reg_path)
        return add_runas()
    runas_value = "~ RUNASADMIN"
    try:
        value = winreg.QueryValueEx(reg_key, exe_path)
    except FileNotFoundError:
        winreg.SetValueEx(reg_key, exe_path, 0, winreg.REG_SZ, runas_value)
    else:
        if runas_value[2:] not in value[0]:
            winreg.SetValueEx(reg_key, exe_path, 0, winreg.REG_SZ, value[0] + ' ' + runas_value[2:])
    winreg.CloseKey(reg_key)

def get_func_offset(dll, export_func_name):
    '''获取dll导出函数的偏移'''
    a = c_void_p.in_dll(dll, export_func_name)
    b = dll._handle
    return addressof(a) - b

def init_python_in_process(hProcess, dll_addr, dllpath, py_code_path=None, open_console=True):
    '''在进程内初始化Python'''
    # 定义 injectpy.dll内的导出函数
    dll = CDLL(dllpath)
    SetDllPath =  dll_addr + get_func_offset(dll, "SetPythonPath")
    SetOpenConsole =  dll_addr + get_func_offset(dll, "SetOpenConsole")
    RunPythonConsole =  dll_addr + get_func_offset(dll, "RunPythonConsole")
    RunPythonFile = dll_addr + get_func_offset(dll, "RunPythonFile")
    RunPythonFileWithPyRun = dll_addr + get_func_offset(dll, "RunPythonFileWithPyRun")
    # 设置Python的路径
    PythonPath = os.path.dirname(sys.executable)
    lpPythonPath = VirtualAllocEx(hProcess, None, MAX_PATH, MEM_COMMIT, PAGE_READWRITE)
    WriteProcessMemory(hProcess, lpPythonPath, c_wchar_p(PythonPath), MAX_PATH, byref(c_ulong()))
    hRemote = DelayCreateRemoteThread(hProcess, None, 0, SetDllPath, lpPythonPath, 0, None)
    VirtualFreeEx(hProcess, lpPythonPath, 0, MEM_RELEASE)
    CloseHandle(hRemote)
    hRemote = DelayCreateRemoteThread(hProcess, None, 0, SetOpenConsole, int(open_console), 0, None)
    CloseHandle(hRemote)
    time.sleep(0.1)
    if not py_code_path:
        hRemote = DelayCreateRemoteThread(hProcess, None, 0, RunPythonConsole, None, 0, None)
        CloseHandle(hRemote)
    else:
        # lpPyCodePath = VirtualAllocEx(hProcess, None, MAX_PATH, MEM_COMMIT, PAGE_READWRITE)
        # WriteProcessMemory(hProcess, lpPyCodePath, c_wchar_p(py_code_path), MAX_PATH, byref(c_ulong()))
        # hRemote = DelayCreateRemoteThread(hProcess, None, 0, RunPythonFile, lpPyCodePath, 0, None)
        lpPyCodePath = VirtualAllocEx(hProcess, None, MAX_PATH, MEM_COMMIT, PAGE_READWRITE)
        WriteProcessMemory(hProcess, lpPyCodePath, c_char_p(py_code_path.encode("ansi")), MAX_PATH, byref(c_ulong()))
        hRemote = DelayCreateRemoteThread(hProcess, None, 0, RunPythonFileWithPyRun, lpPyCodePath, 0, None)
        time.sleep(3)
        VirtualFreeEx(hProcess, lpPyCodePath, 0, MEM_RELEASE)
        CloseHandle(hRemote)


def inject_dll(pid, open_console, py_code_path, dllpath=None):
    '''注入dll到给定的进程，返回http端口'''
    add_runas()
    if not dllpath:
        raise Exception("给定的dllpath不存在")
    dllpath = os.path.abspath(dllpath)
    if not os.path.exists(dllpath):
        raise Exception('给定的dllpath不存在')
    dllname = os.path.basename(dllpath)
    dll_addr = getModuleBaseAddress(dllname, pid)
    if dll_addr:
        print("当前进程已存在相同名称的dll")
        return dll_addr
    # 通过微信进程pid获取进程句柄
    hProcess = OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    # 在微信进程中申请一块内存
    lpAddress = VirtualAllocEx(hProcess, None, MAX_PATH, MEM_COMMIT, PAGE_READWRITE)
    # 往内存中写入要注入的dll的绝对路径
    WriteProcessMemory(hProcess, lpAddress, c_wchar_p(dllpath), MAX_PATH, byref(c_ulong()))
    # 在微信进程内调用LoadLibraryW加载dll
    hRemote = DelayCreateRemoteThread(hProcess, None, 0, LoadLibraryW, lpAddress, 0, None)
    VirtualFreeEx(hProcess, lpAddress, 0, MEM_RELEASE)
    CloseHandle(hRemote)
    dll_addr = getModuleBaseAddress(dllname, pid)
    init_python_in_process(hProcess, dll_addr, dllpath, py_code_path, open_console)
    # 关闭句柄
    CloseHandle(hProcess)
    return dll_addr


def uninject_dll(pid, dllname):
    dll_addr = getModuleBaseAddress(dllname, pid)
    hProcess = OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    while dll_addr:
        hRemote = DelayCreateRemoteThread(hProcess, None, 0, FreeLibrary, dll_addr, 0, None)
        CloseHandle(hRemote)
        dll_addr = getModuleBaseAddress(dllname, pid)
    CloseHandle(hProcess)


def inject_python_to_process(pid, open_console=True, py_code_path=None):
    python_bit = platform.architecture()[0][:2]
    pwd = os.path.abspath(os.path.dirname(__file__))
    dll_new_path = os.path.join(pwd, "dll", f"injectpy{python_bit}.dll")
    addr = inject_dll(pid, open_console, py_code_path, dllpath=dll_new_path)
    print("注入后的dll基址: ", hex(addr))
    return addr

def init_monitor(_main_path):
    '''_main_path: __main__的路径'''
    event = Event()
    event.set()

    path = os.path.dirname(_main_path)
    print(f"开始监听目录({path})下的代码文件变化！")
    monitor_dir(path, event, _main_path, interval=2, only_import_exist=False)
    
    event.clear()

def inject_python_and_monitor_dir(process_name, _main_path, open_console=True, on_startup=None):
    pid = get_pid_by_name(process_name)
    if not pid:
        raise Exception("请先启动进程后再注入!")
    _main_path = os.path.abspath(_main_path)
    if pid == os.getpid():
        if on_startup and callable(on_startup):
            on_startup(_main_path)
        init_monitor(_main_path)
    else:
        inject_python_to_process(pid, open_console=open_console, py_code_path=_main_path)

def inject_python_and_open_console(process_name, open_console=True):
    pid = get_pid_by_name(process_name)
    if not pid:
        raise Exception("请先启动进程后再注入!")
    inject_python_to_process(pid, open_console=open_console, py_code_path=None)