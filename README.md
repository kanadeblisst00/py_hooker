## 原理讲解

1. [怎么写一个32位任意地址的Hook](https://mp.weixin.qq.com/s/gAVt731tfOiS5o7U1b3haQ)
2. [detour的编译和封装](https://mp.weixin.qq.com/s/wbsjxv7Zt67pMi5ZYD0cfQ)
3. [keystone和beaengine的编译](https://mp.weixin.qq.com/s/n4kYvjDduUgRzZLDz5Acfg)
4. [封装32位和64位hook框架](https://mp.weixin.qq.com/s/7WnA0YIkiIqgOttuUnPPqw)

## 功能

将注入Python注入到任意进程后，实现hook和内部函数调用

## 安装

pip install py-process-hooker==0.1.2

## 使用

以微信进程为例, 使用Python运行以下代码就会监听并执行当前目录下的py文件。具体看[WeChat-PyRobot](https://github.com/kanadeblisst00/WeChat-PyRobot) 

```python
from py_process_hooker import inject_python_and_monitor_dir


if __name__ == "__main__":
    process_name = "WeChat.exe"
    open_console = True
    inject_python_and_monitor_dir(process_name, __file__, open_console=open_console)
```

#### 案例

1. [在windows11上编译python](https://mp.weixin.qq.com/s/nJq8XX203Wc_gwT5hSWYZA)
2. [将python注入到其他进程并运行](https://mp.weixin.qq.com/s/gvV9GRQZbvxHQSjfDieiqw)
3. [注入Python并使用ctypes主动调用进程内的函数和读取内存结构体](https://mp.weixin.qq.com/s/Dy8-nJPoXJp9_ZrrwOrC0w)
4. [调用汇编引擎实战发送文本和图片消息(支持32位和64位微信)](https://mp.weixin.qq.com/s/PJZDf5937SsncGU-RhZ3tA)
5. [允许Python加载运行py脚本且支持热加载](https://mp.weixin.qq.com/s/FWW1FecRo_yAhh9eLScAoA)
6. [利用汇编和反汇编引擎写一个x86任意地址hook，实战Hook微信日志](https://mp.weixin.qq.com/s/7WnA0YIkiIqgOttuUnPPqw)
7. [封装Detour为dll，用于Python中x64函数 hook，实战Hook微信日志](https://mp.weixin.qq.com/s/wbsjxv7Zt67pMi5ZYD0cfQ)
8. [实战32位和64位接收消息和消息防撤回](https://mp.weixin.qq.com/s/UUO27gRLdIKzTlaSuwiV0w)
9. 实战读取内存链表结构体(好友列表)
10. 做一个僵尸粉检测工具
11. 根据bug反馈和建议进行细节上的优化
12. 其他功能看心情加

