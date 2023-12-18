import os
from threading import Lock
from .winapi import *

# x86寄存器的结构体
class RegisterContext(Structure):
    _fields_ = [
        ('EFLAGS', DWORD),
        ('EDI', DWORD),
        ('ESI', DWORD),
        ('EBP', DWORD),
        ('ESP', DWORD),
        ('EBX', DWORD),
        ('EDX', DWORD),
        ('ECX', DWORD),
        ('EAX', DWORD),
    ]
# 保存被修改的机器码的类型
unsigned_char_p = c_ubyte * 20
# 回调函数类型
hookFuncPointer = WINFUNCTYPE(void, POINTER(RegisterContext))

class Hook:
    # 保存单例
    _instance = None
    _instance_lock = Lock()
    # 保存Hook的所有地址
    _address = {}
    _callback = {}
    _address_lock = Lock()

    def __init__(self) -> None:
        pwd = os.path.abspath(os.path.dirname(__file__))
        path = os.path.join(pwd, "dll", "AnyHook.dll")
        self._dll = CDLL(path)
        self.HookAnyAddress, self.UnHookAnyAddress = self.init_func()
    
    def __new__(cls, *args, **kwargs):
        '''多线程单例模式'''
        with cls._instance_lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
            return cls._instance
    
    def __del__(self):
        '''当实例被回收时，取消之前Hook的所有地址'''
        with self._address_lock:
            address = self._address.copy()
        for i in address:
            self.unhook(int(i, 16))
    
    def init_func(self):
        '''初始化dll中的hook函数'''
        HookAnyAddress = self._dll.HookAnyAddress
        HookAnyAddress.argtypes = (c_ulong, hookFuncPointer, unsigned_char_p, c_ulong)
        HookAnyAddress.restype = c_ulong

        UnHookAnyAddress = self._dll.UnHookAnyAddress
        UnHookAnyAddress.argtypes = (c_ulong, unsigned_char_p, c_ulong)
        UnHookAnyAddress.restype = c_ulong
        return HookAnyAddress, UnHookAnyAddress
    
    def hookFunc(self, pcontext:POINTER(RegisterContext)) -> None:
        '''示例回调函数'''
        context = pcontext.contents
        print("pcontext: ", hex(addressof(context)))
        print("EFLAGS: ",hex(context.EFLAGS))
        print("EDI: ",hex(context.EDI))
        print("ESI: ",hex(context.ESI))
        print("EBP: ",hex(context.EBP))
        print("ESP: ",hex(context.ESP))
        print("EBX: ",hex(context.EBX))
        print("EDX: ",hex(context.EDX))
        print("ECX: ",hex(context.ECX))
        print("EAX: ",hex(context.EAX))

    def hook(self, hookAddress, hookFunc=None):
        '''
        hookAddress: hook的内存地址
        hookFunc: 回调函数
        '''
        with self._address_lock:
            hex_hookAddress = hex(hookAddress)
            if hex_hookAddress in self._address:
                print("当前地址已经被hook！")
                return
            old_code = unsigned_char_p()
            hookFunc = hookFunc or self.hookFunc
            pfunc = hookFuncPointer(hookFunc)
            hookCodeSize = self.HookAnyAddress(hookAddress, pfunc, old_code, 20)
            if not hookCodeSize:
                print(f"hook失败, 地址: {hookAddress}!")
                return
            print("hook成功, 地址: ", hex_hookAddress)
            self._address[hex_hookAddress] = old_code[:hookCodeSize]
            self._callback[hex_hookAddress] = pfunc
            return hookCodeSize

    def unhook(self, hookAddress):
        with self._address_lock:
            hex_hookAddress = hex(hookAddress)
            if hex_hookAddress not in self._address:
                print("当前地址没有被hook！")
                return
            print("取消hook成功, 地址: ", hex_hookAddress)
            old_code_array = self._address[hex_hookAddress]
            size = len(old_code_array)
            old_code = unsigned_char_p(*old_code_array)
            self.UnHookAnyAddress(hookAddress, old_code, size)
            self._address.pop(hex_hookAddress)
            self._callback.pop(hex_hookAddress)