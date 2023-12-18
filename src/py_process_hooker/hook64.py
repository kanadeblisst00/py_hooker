import os
from threading import Lock
from .winapi import *


class Hook:
    _instance = None
    _instance_lock = Lock()
    _callback = {}
    _callback_lock = Lock()

    def __init__(self) -> None:
        pwd = os.path.abspath(os.path.dirname(__file__))
        path = os.path.join(pwd, "dll", "DetourHook.dll")
        self._dll = CDLL(path)
    
    def __new__(cls, *args, **kwargs):
        with cls._instance_lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
            return cls._instance
    
    def __del__(self):
        with self._callback_lock:
            address = self._callback.copy()
        for i in address:
            self.unhook(int(i, 16))
    
    def hook(self, old_func_pointer:c_uint64, func_pointer, new_func):
        with self._callback_lock:
            addr = hex(old_func_pointer.value)
            if addr in self._callback:
                print("当前地址已经被hook！")
                return
            print("hook成功, 地址: ", addr)
            DetourHookFunction = self._dll.DetourHookFunction
            DetourHookFunction.argtypes = (POINTER(c_uint64), func_pointer)
            DetourHookFunction.restype = c_uint64
            pfunc = func_pointer(new_func)
            self._callback[addr] = (old_func_pointer, func_pointer, pfunc)
            DetourHookFunction(byref(old_func_pointer), pfunc)  

    def unhook(self, old_func_addr):
        with self._callback_lock:
            addr = hex(old_func_addr)
            if addr not in self._callback:
                print("当前地址没有被hook！")
                return
            print("取消hook成功, 地址: ", addr)
            old_func_pointer, func_pointer, pfunc = self._callback.pop(addr)
            DetourUnHookFunction = self._dll.DetourUnHookFunction
            DetourUnHookFunction.argtypes = (POINTER(c_uint64), func_pointer)
            DetourUnHookFunction.restype = c_uint64
            DetourUnHookFunction(byref(old_func_pointer), pfunc)  





















