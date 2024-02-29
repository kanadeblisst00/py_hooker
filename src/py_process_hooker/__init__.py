# -*- coding: utf-8 -*-
'''
Time    : 2023-12-12
Author  : kanadeblisst
FileName: py_process_hooker
github ：https://github.com/kanadeblisst00/py_hooker
国内仓库: http://www.pygrower.cn:21180/kanadeblisst/py_hooker
Function:  Inject python into other processes and implement 
           Hook and active calls, supporting x86 and x64
'''
import platform
from .inject_dll import inject_python_and_monitor_dir, inject_python_and_open_console

if "64" in platform.architecture()[0]:
    from .hook64 import Hook
else:
    from .hook32 import Hook


__version__ = "0.2.1"


__all__ = [
    "inject_python_and_monitor_dir",
    "inject_python_and_open_console",
    "Hook"
]



