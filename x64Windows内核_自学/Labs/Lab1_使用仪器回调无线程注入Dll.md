# Lab-1-1 InstrumentationCallBack注入

# 0x1 注入原理

- 通过InstCall的每次系统调用会执行(一个正常的进程不可能不会执行系统调用),去执行自己的shellcode
- 驱动中读写文件DLL,进行申请Dll空间到待注入的进程(和内存注入完全一样)
- 最后shellcode重定位DLL,RIP交给DLL MAIN,去执行自己的DLL

# 0x2 实验细节

## InstCall的shellcode

首先是ShellCode,每次执行完系统调用执行回调,r10是原来的RIP,因此需要jmp r10

而InstCall去执行的shellcode如下

```c++
char g_InstCallBackShellCode[] =
{
	0x51, //push  rcx   
	0x52, //push  rdx
	0x53, //push  rbx												//
	0x55, 															//
	0x56, 															//
	0x57, 															//
	0x41, 0x50, 													//
	0x41, 0x51, 													//
	0x41, 0x52, 													//
	0x41, 0x53, 													//
	0x41, 0x54, 													//
	0x41, 0x55, 													//
	0x41, 0x56, 													//
	0x41, 0x57, 													//
	//上面都是保存寄存器
	// sub rsp,0x20
	0x48,0x83,0xec,0x28,
	
	//00000217F568001 | 48:83EC 20 | sub rsp,0x20 |
	//00000217F568001 | 48 : 83C4 20 | add rsp,0x20 |
	//Call ShellCode 进行重定位

	0x48, 0xB9, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,  //mov rcx,重定位数据

	0xFF, 0x15, 0x00, 0x00, 0x00, 0x00, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,//call 地址
	
	//add rsp,0x20
	0x48,0x83,0xc4,0x28,
	//pop 寄存器
	0x41, 0x5F,
	0x41, 0x5E,
	0x41, 0x5D,
	0x41, 0x5C,
	0x41, 0x5B,
	0x41, 0x5A,
	0x41, 0x59,
	0x41, 0x58,
	0x5F,
	0x5E,
	0x5D,
	0x5B,
	0x5A,
	0x59,
	0x41, 0xFF, 0xE2,  //jmp r10 返回

	//71个 绝对地址在这个地方
	0,0,0,0,0,0,0,0
};

```

## 坑1

在执行ShellCode的时候,有一个FF 15 无限CALL

这里的坑是不能之间FF 15 00 00 00 00 Addr

因为这个Addr是不算做指令长度的,因此Ret的时候返回到CALL下面的地址去执行,导致崩溃

## 坑2

因为是汇编ShellCode去调用重定位**ShellCode**,重定位的ShellCode。

而重定位ShellCode不是用汇编写的,是遵循x64调用约定,因此调用之前需要**提升堆栈**

## 坑3

提升堆栈的时候,如果提升不按0x10对齐,会崩溃,c0000005错误

这是因为重定位的函数GetProcAddress,用了movaps这个指令,这个指令操作数必须是0x10对齐!

## 重定位的ShellCode

## 坑4

经过测试,如果InstCall有值,调用函数会导致程序卡死,暂时不清楚原因

解决方法如下:

```C
void __stdcall ShellCode(Manual_Mapping_data* pData) {
	
	//DbgBreakPoint();

	if (!pData->bFirst) return;

	//成功 立刻设置 防止重入
	pData->bFirst = false;

	pData->bStart = true;
    
    ....重定位操作
    //开始 设置,让驱动卸载掉CallBack
	
	while (!pData->bContinue);
	//执行DllMain函数

	((f_DLL_ENTRY_POINT)(pBase + pOpt->AddressOfEntryPoint))(pBase, 1, 0);
}
```

ManualData是驱动分配的内存,是待注入进程的内存。

设置First是防止重入,设置Start是通知驱动,此时应该取消InstCallBack,驱动代码如下

```c++
//判断什么时候可以去掉CallBack
	if(ManualData && MmIsAddressValid(ManualData))
	while (!((Manual_Mapping_data*)ManualData)->bStart);

	//卸载
	inst_callback_set_callback(0);
	if (ManualData && MmIsAddressValid(ManualData)) {
		
		//执行为只可执行
		//DbgBreakPoint();
		//同时抹除掉PE头的特征
		*(PUCHAR)((((Manual_Mapping_data*)ManualData))->pBase) = 0;
		//PVOID Base = ((Manual_Mapping_data*)ManualData)->pBase;
		//ZwProtectVirtualMemory(NtCurrentProcess(), &Base, &ReProtectSize, PAGE_EXECUTE, (PULONG)&ReProtectSize);

		//可以继续执行了
		((Manual_Mapping_data*)ManualData)->bContinue = true;
	}
```

## 过BE的隐藏内存和小坑

BE会查询可读写可执行的内存,查到轻则打乱重则游戏闪退

过BE的隐藏内存是内存时候学到的,修改MMPFNDATABASE的指定物理地址的**原始PTE**

不是原型PTE,这个是私有内存。

改这个即可过BE内存查询。

这里有个小坑,一定要隐藏完整,

```c++
for(size_t index=0;index<DllSize;index+=PAGE_SIZE)
	PageAttrHide::ChangeVadAttributes((UINT64)pStartMapAddr+index, MM_NOACCESS);

	PageAttrHide::ChangeVadAttributes((UINT64)pManualMapData, MM_NOACCESS);
	PageAttrHide::ChangeVadAttributes((UINT64)pShellCode, MM_NOACCESS);
	PageAttrHide::ChangeVadAttributes((UINT64)*inst_callbak_addr, MM_NOACCESS);
```

pStartMapAddr是整个DLL分配到要注入的进程的,他很大,超过一个PAGE_sIZE,因此记得循环,整个隐藏。