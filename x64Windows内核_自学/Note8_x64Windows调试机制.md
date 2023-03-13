

# 0x0参考

《WRK源码》

《火哥内核视频》

# 0x1 Windows调试体系

在Windows中,调试器是基于事件处理的,不是基于状态机的。

因此在内核中,是在进程与被调试进程之间建立通道进行通信的,即==DebugPort:调试对象==

被调试进程中产生事件时,会把事件放在DebugPort的一个事件链表中。而调试器接受事件通知,去DebugPort拿调试事件。

常见的调试事件如

- 创建进线程
- 进线程结束
- ==异常==
- 模块加卸载
- 打印日志:OutputStringA

最核心的便是异常，其他的调试事件一般是用记录的。

## 0x1-1 调试对象的建立

Windows调试必须先建立管道,才能在调试进程和被调试进程传递信息。而管道就是调试对象。

调试器拥有调试对象句柄从而对被调试进程进行操作。被调试进程EPROCESS.DebugPort存值以便于往里面写入DeBugEvent。

### 0x1-1-1 DebugActiveProcess



```c++
BOOL __stdcall DebugActiveProcess(DWORD dwProcessId);
```

这个函数是调试通道建立的开始,他的主要功能就是

- 创建调试对象(DEBUG_OBJECT)
- 根据传入的Pid打开句柄(==权限问题==),调用__imp_DbgUiDebugActiveProcess,把DebugPort挂上去。

DbgUiConnectToDbg即创建调试对象,判断是否创建成功。

```assembly
mov     [rsp+arg_0], rbx
push    rdi             ; 保留非易失寄存器
sub     rsp, 20h
mov     ebx, ecx
call    cs:__imp_DbgUiConnectToDbg ; 先创建一个调试对象
nop     dword ptr [rax+rax+00h]
test    eax, eax
jns     short DebugPortCreateSuccess ; 因此想要调试,首先得打开进程
```

然后根据Pid打开进程获取句柄,调用`__imp_DbgUiDebugActiveProcess()`将被调试进程DEBUG_PORT端口和创建的调试对象句柄联系起来。

```assembly
DebugPortCreateSuccess: ; 因此想要调试,首先得打开进程
mov     ecx, ebx
call    ProcessIdToHandle ; 打开进程,获取句柄
mov     rbx, rax
test    rax, rax
jz      short OpenFailed
mov     rcx, rax        ; 被调试进程句柄
call    cs:__imp_DbgUiDebugActiveProcess ; 初始化调试对象信息
nop     dword ptr [rax+rax+00h]
mov     edi, eax
mov     rcx, rbx
test    eax, eax
jns     short InitDebugPortSuccess ; 关闭句柄返回
OpenFaild:
;清理资源,关闭句柄。
```

### 0x1-1-2 DbgUiConnectToDbg

前文提到,这个用于创建调试对象,创建过程是ntdll!DbgUiConnectToDbg->nt!NtCreateDebugObject

在这个函数中,进行了一些简单判断,判断是否已经在调试别的程序中。

```assembly
mov     rax, gs:_TEB.NtTib.Self
xor     ecx, ecx
cmp     [rax+(_TEB.DbgSsReserved+8)], rcx ; 判断是否已经有调试
jnz     short HasDebugge
```

他判断是否有被调试进程是通过TEB.DbgSsReserved+8的位置,事实上,这个地方存的就是句柄。

如果没有,则调用NtCreateDebugObject进入内核进程创建对象。

```assembly
mov     [rsp+28h], rcx
lea     r8, [rsp+20h]   ; 传地址 其实是OBJECT_ATTRIBUTES
mov     [rsp+38h], ecx
xorps   xmm0, xmm0
mov     [rsp+30h], rcx
mov     r9d, 1          ; 传参
movdqu  xmmword ptr [rsp+40h], xmm0
mov     dword ptr [rsp+20h], 30h
mov     edx, 1F000Fh    ; 传参
mov     rcx, gs:_TEB.NtTib.Self
add     rcx, _TEB.DbgSsReserved+8
call    NtCreateDebugObject 


```

而NtCreateDebugObject函数声明是

```c++
NTSTATUS
NtCreateDebugObject (
    OUT PHANDLE DebugObjectHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes,
    IN ULONG Flags
    );
```

由参数推出,第一个参数,DebugObjectHandle就是`_TEB.DbgSsReserved+8`位置,也就是调试对象的句柄。

值得一提的是,DesiredAccess是对于调试对象句柄的权限。

### 0x1-1-3 nt!NtCreateDebugObject

这个函数只有两个作用

- 创建调试对象
- 根据参数DesiredAccess作为调试对象权限存入调试进程的句柄表中

首先检查一些参数,这是R3->R0的常规操作。

然后创建调试对象,使用==ObCreateObjectEx==,所有内核对象都是通过它创建的,包括ETHREAD,EPROCESS等

```assembly
CreateDebugObject:      ; 调试对象类型
mov     rdx, cs:DbgkDebugObjectType
and     qword ptr [rsp+48h], 0
lea     rax, [rsp+88h+pObject]
mov     [rsp+40h], rax  ; pObject
and     dword ptr [rsp+38h], 0
and     dword ptr [rsp+30h], 0
mov     dword ptr [rsp+28h], 68h ; ObjectSize
mov     r9b, r10b
mov     cl, r10b        ; AccessMode
call    ObCreateObjectEx ; 创建调试对象
test    eax, eax
js      Ret
```

调试对象的结构如下:

```c++
typedef struct _DEBUG_OBJECT {
    //
    // Event thats set when the EventList is populated.
    //
    KEVENT EventsPresent;
    //
    // Mutex to protect the structure
    //
    FAST_MUTEX Mutex;
    //
    // Queue of events waiting for debugger intervention
    //
    LIST_ENTRY EventList;
    //
    // Flags for the object
    //
    ULONG Flags;
} DEBUG_OBJECT, *PDEBUG_OBJECT;
```

**其中EventsPresent**的意义是方便让调试器的调试循环捕捉,一旦在链表中有了要处理的调试事件,就会用KeSetEvent设置事件信号(==后面会有体现==)。

**而Mutex**的意义便是多线程操作链表时候的同步作用。

**EventList是链表头**,链接DEBUG_EVENT所有事件

**flags**则表明DebugObject属性,如下值

```c++
#define DEBUG_OBJECT_DELETE_PENDING (0x1) // Debug object is delete pending.
#define DEBUG_OBJECT_KILL_ON_CLOSE  (0x2) // Kill all debugged processes on close
```

若为1,说明DebugObject无效

创建对象成功后,进行简单初始化,如链表清空操作

```assembly
mov     rbx, [rsp+88h+pObject] ; 调试对象进行赋值
mov     [rbx+_DEBUG_PORT.Mutex.Count], 1 ; 参考WRK的DEBUG_PORT对象
and     [rbx+_DEBUG_PORT.Mutex.Owner], 0 ; 初始化互斥体,用于插入链表时候的同步
and     [rbx+_DEBUG_PORT.Mutex.Contention], 0
lea     rcx, [rbx+_DEBUG_PORT.Mutex.Event] ; Event
xor     r8d, r8d        ; State
lea     edx, [r8+1]     ; Type
call    KeInitializeEvent
lea     rax, [rbx+_DEBUG_PORT.EventList]
mov     [rax+8], rax
mov     [rax], rax      ; 情况链表 自己指向自己
xor     r8d, r8d        ; State
xor     edx, edx        ; Type
mov     rcx, rbx        ; Event
call    KeInitializeEvent
test    sil, 1          ; R3 flags
jz      short Equal
mov     dword ptr [rbx+_DEBUG_PORT.Flags], 2  
jmp     short loc_140883589
Equal:
and     dword ptr [rbx+_DEBUG_PORT.Flags], 0
```

**其中sil即R3->R0传入的flags**,不难发现,如果传入1,则代表调试关闭时关闭所有调试进程(==出现场景为调试子进程==),如果传入0,则不会关闭所有被调试进程。

在创建完对象之后,进行wow64进程的判断,如果调试进程是32位的,那么flags | 4

```assembly
mov     rax, gs:188h
mov     rcx, [rax+_ETHREAD.Tcb._union_90.ApcState.Process]
mov     rax, [rcx+_EPROCESS.WoW64Process] ; 这是调试器的线程
test    rax, rax
jz      short x64Bit
or      dword ptr [rbx+_DEBUG_PORT.Flags], 4 ; 即flags & 4 就是wow64
x64Bit:
xxxxx
```

然后把调试对象插入到调试进程的句柄表中,其中句柄的权限就是R3传入的DesriedAccess;

顺带也可以发现,产生的句柄确实放在了_TEB.DbgSsReserved+8这个位置。

```assembly
mov     r8d, r14d       ; r14就是R3传过来的DesriedAccess
xor     edx, edx
mov     rcx, [rsp+88h+pObject]
call    ObInsertObjectEx ; InsertObject的作用就是把对象查到句柄表里面
mov     ecx, eax
test    eax, eax
js      short Ret
mov     rax, [rsp+88h+Handle] 
mov     [rdi], rax      ; 这是TEB的那个位置,用于保存句柄
Ret:
;进行释放资源的操作
```

自此调试对象创建完毕。

## 0x1-2调试对象挂入被调试进程

在DebugActiveProcess中,创建完调试对象之后,则开始进行与被调试对象挂入操作。

调用如下函数进行挂入:

```c++
NTSTATUS __fastcall DbgUiDebugActiveProcess(__int64 ProcessHandle)
{
  __int64 hProcess; // rdi
  signed int status; // ebx

  hProcess = ProcessHandle;
  status = NtDebugActiveProcess(ProcessHandle, NtCurrentTeb()->DbgSsReserved[1]);
  if ( status >= 0 )
  {
    status = DbgUiIssueRemoteBreakin(hProcess);
    if ( status < 0 )
      ZwRemoveProcessDebug(hProcess, NtCurrentTeb()->DbgSsReserved[1]);
  }
  return (unsigned int)status;
}
```

函数主要功能即调用NtDebugActiveProcess,传入被调试进程句柄和调试对象句柄,在内核进行挂载。

在挂入成功之后,调用`DbgUiIssueRemoteBreakin()`。

这个函数的作用是创建一个远程线程,让远程线程指向int3产生异常,被调试器捕获。

这就是为什么用调试器附加进程,总是会断在一个系统断点。

```c++
__int64 __fastcall DbgUiIssueRemoteBreakin(__int64 hProcess)
{
  status = RtlpCreateUserThreadEx(
             hProcess,
             0i64,
             2,
             0,
             0i64,
             0x4000i64,
             v3,
             (__int64)DbgUiRemoteBreakin,       // 新建线程的地址
             0i64,
             &v5,
             (__m128i *)&v4);
  if ( (status & 0x80000000) == 0 )
    NtClose(v5);
  return status;
}
```

`DbgUiRemoteBreakin`是新建线程的地址,在进行简单判断之后就会调用`DbgBreakPoint();`

```c++
void __noreturn DbgUiRemoteBreakin()
{
  if ( (NtCurrentPeb()->BeingDebugged || MEMORY[0x7FFE02D4] & 2) && !(NtCurrentTeb()->_union_108.SameTebFlags & 0x20) )
  {
    if ( UseWOW64 )
    {
      if ( g_LdrpWow64PrepareForDebuggerAttach )
        g_LdrpWow64PrepareForDebuggerAttach();
    }
    DbgBreakPoint();//执行Int3
  }
  RtlExitUserThread(0i64);
}
```

值得一提的是,在`DbgUiDebugActiveProcess`中,如果`DbgUiIssueRemoteBreakin`执行失败,则会执行

```c++
  if ( status < 0 )
      ZwRemoveProcessDebug(hProcess, NtCurrentTeb()->DbgSsReserved[1]);
```

而`DbgUiIssueRemoteBreakin`执行失败只有一个原因,即创建远程线程失败。因此要调试还需要具有远程创建线程的句柄权限。

### 0x1-2-1 nt!NtDebugActiveProcess

它是被调试进程和调试对象建立起来联系核心函数。

声明如下:

```c++
NTSTATUS
NtDebugActiveProcess (
    IN HANDLE ProcessHandle,
    IN HANDLE DebugObjectHandle
    );
```

函数首先根据句柄找到进程

```assembly
mov     r8, cs:PsProcessType
and     qword ptr [r11+18h], 0
mov     bpl, byte ptr [rax+_ETHREAD.Tcb._union_171.UserAffinity.Reserved] ; PreviousMode
lea     rax, [r11+18h]  ; pObject rsp+0x80
and     qword ptr [r11-28h], 0
mov     r9b, bpl
mov     [r11-40h], rax
mov     dword ptr [rsp+68h+Object], 4F676244h
call    ObReferenceObjectByHandleWithTag ; 获取进程对象
```

然后根据进程进行一些判断,基本就是

- 是否调试自己
- 是否是系统进程
- 是否是wow64

```assembly
mov     rax, gs:188h
mov     rdi, [rsp+68h+pDebugProcess]
mov     rsi, [rax+_ETHREAD.Tcb._union_90.ApcState.Process]
cmp     rdi, rsi        ; 判断是不是在调试自己
jz      DebugProcessErr
cmp     rdi, cs:PsInitialSystemProcess ; 判断一下是不是这个进程 就是system进程
jz      DebugProcessErr
mov     rax, [rdi+_EPROCESS.WoW64Process]
test    rax, rax
jz      x64Bit 
;进行调试进程被调试进程检查
; 如果被调试64 调试32 无法调试
```

检查无误之后,获取调试对象

```assembly
GetDebugObject:         ; ObjectType
mov     r8, cs:DbgkDebugObjectType
lea     rax, [rsp+68h+pDebugObject]
and     [rsp+68h+var_40], 0
mov     r9b, bpl        ; AccessMode
and     [rsp+68h+pDebugObject], 0
mov     edx, 2          ; DesiredAccess
mov     rcx, r14        ; Handle
mov     [rsp+68h+Object], rax ; Object
call    ObReferenceObjectByHandle
```

此外,获取RunDown 锁,防止进程结束

```assembly
lea     rbp, [rdi+_EPROCESS.RundownProtect]
mov     rcx, rbp
call    ExAcquireRundownProtection_0 ; 获取被调试对象的RunDown锁
mov     rsi, [rsp+68h+pDebugObject] ; 这个可以反调试 但是不要用
test    al, al
jz      short RunDownProtectErr
```

之后进入核心代码,发送==假消息模拟==

> 调试假消息的意义在于附加时进程已经创建,无法还原线程进程创建时场景,因此采取模拟发送假消息方式进行折中,还原进程刚创建时的调试信息不会遗漏。

```assembly
lea     r8, [rsp+68h+var_28]
mov     rdx, rsi        ; DebugObject
mov     rcx, rdi        ; DebugProcess
call    DbgkpPostFakeProcessCreateMessages ; 创建进程创建的假消息 其实就是进程已经创建过了 还得接受一下消息
                        ; 模拟一下正常调试信息
                        ; 注意是创建,不会发送!
mov     r9, [rsp+68h+var_28]
mov     r8d, eax
mov     rdx, rsi        ; DebugPort
mov     rcx, rdi        ; DebugProcess
call    DbgkpSetProcessDebugObject ; 把DebugPort写入被调试进程
                        ; 参考WRK
                        ; 并发送消息上一个函数模拟的假消息
mov     rcx, rbp
mov     ebx, eax
call    ExReleaseRundownProtection_0 ; 释放锁
jmp     short release
```

核心函数便是

```c++
NTSTATUS
DbgkpPostFakeProcessCreateMessages (
    IN PEPROCESS Process,
    IN PDEBUG_OBJECT DebugObject,
    IN PETHREAD *pLastThread
    );
```

```c++
NTSTATUS
DbgkpSetProcessDebugObject (
    IN PEPROCESS Process,
    IN PDEBUG_OBJECT DebugObject,
    IN NTSTATUS MsgStatus,
    IN PETHREAD LastThread
    );
```

## 0x1-3发送假消息

在调试器附加之后,会发送假消息模拟进程创建。这时候DebugPort还没有挂入到被调试进程。无法直接将消息写入Process.DebugPort,==Windows采取采取传入DebugPort变量,消息写入变量中==,而非Process.DebugPort中。

然后在`DbgkpSetProcessDebugObject`中进行设置DebugPort挂入被调试进程。

### 0x1-3-1 DbgkpPostFakeProcessCreateMessages

```c++
__int64 __fastcall DbgkpPostFakeProcessCreateMessages(_EPROCESS *DebugProcess, _DEBUG_PORT *DebugObject, __int64 *a3)
{
  v3 = a3;
  v4 = 0i64;
  pFirstThread = 0i64;
  v10 = 0i64;
  pLastThread = 0i64;
  DebugObject_1 = DebugObject;
  v11 = 0i64;
  DebugProcess_1 = DebugProcess;
  v12 = 0i64;
  result = DbgkpPostFakeThreadMessages(DebugProcess, DebugObject, 0i64, &pFirstThread, &pLastThread);// 发送线程假消息
  if ( (signed int)result >= 0 )
  {
    KiStackAttachProcess((ULONG_PTR)DebugProcess_1, 0, (__int64)&v10);
    DbgkpPostModuleMessages(DebugProcess_1, pFirstThread, DebugObject_1);// 发送模块消息
    KiUnstackDetachProcess(&v10, 0i64);
    ObfDereferenceObjectWithTag((ULONG_PTR)pFirstThread);
    result = 0i64;
    v4 = pLastThread;
  }
  *v3 = (__int64)v4;
  return result;
}
```

首先是发送假线程消息,在`DbgkpPostFakeProcessCreateMessages()`中

```c++
result = DbgkpPostFakeThreadMessages(DebugProcess, DebugObject, 0i64, &pFirstThread, &pLastThread);// 发送线程假消息
```

在此函数中,主要进行了如下操作

- 判断是否是不能调试的进线程,入system的线程,直接跳过不发送假消息
- 遍历被调试进程所有线程,获取线程结构体,初始化==_DBGKM_APIMSG==结构体

此结构是后面用于初始化DEBUG_EVENT的结构体,DEBUG_EVENT是用于挂在DEBUG_OBJECT.EventList链表中的。

如下代码,根据ApiNumber=2,初始化ApiMsg结构体,

_DBGKM_APIMSG结构如下

```c++
typedef struct _DBGKM_APIMSG {
    PORT_MESSAGE h;
    DBGKM_APINUMBER ApiNumber; //枚举
    NTSTATUS ReturnedStatus;
    union {
        DBGKM_EXCEPTION Exception;
        DBGKM_CREATE_THREAD CreateThread;
        DBGKM_CREATE_PROCESS CreateProcessInfo;
        DBGKM_EXIT_THREAD ExitThread;
        DBGKM_EXIT_PROCESS ExitProcess;
        DBGKM_LOAD_DLL LoadDll;
        DBGKM_UNLOAD_DLL UnloadDll;
    } u;
} DBGKM_APIMSG, *PDBGKM_APIMSG;
```

其中h用于串口联网调试。

ApiNumber则是如下枚举

```c
typedef enum _DBGKM_APINUMBER {
  DbgKmExceptionApi,
  DbgKmCreateThreadApi,
  DbgKmCreateProcessApi,
  DbgKmExitThreadApi,
  DbgKmExitProcessApi,
  DbgKmLoadDllApi,
  DbgKmUnloadDllApi,
  DbgKmMaxApiNumber
} DBGKM_APINUMBER;
```

**DbgkpPostFakeThreadMessages该函数操作如下**

```c++
*(_DWORD *)&ApiMsg.ApiNumber = 2;    
Section = (_SECTION *)Process_2->SectionObject;
if ( Section )
  *(_QWORD *)&ApiMsg.u[11] = DbgkpSectionToFileHandle(Section);// 就是返回文件句柄的
else
  *(_QWORD *)&ApiMsg.u[11] = 0i64;
*(_QWORD *)&ApiMsg.u[19] = Process_2->SectionBaseAddress;// BaseOfImage
KeStackAttachProcess(Process_2, (_KAPC_STATE *)&Apc);
ntHead = (IMAGE_NT_HEADERS64 *)RtlImageNtHeader(Process_2->SectionBaseAddress);
if ( ntHead )
{
	*(_QWORD *)&ApiMsg.u[43] = 0i64;
	*(_DWORD *)&ApiMsg.u[27] = ntHead->FileHeader.PointerToSymbolTable;// 符号表
	*(_DWORD *)&ApiMsg.u[31] = ntHead->FileHeader.NumberOfSymbols;
}
          
KeUnstackDetachProcess(&Apc);
status = DbgkpQueueMessage(Process_2, StartThread_1, &ApiMsg, flags, DebugObject_1);// 将信息插入DebugObject
                                                // 这个函数就是插入DebugObject并设置DebugObject的等待位为等待
                                                // 现在我们在发假消息的时候调用,他的作用仅仅是初始化DebugPort,填DebugEvent
```

在初始化完ApiMsg之后,调用`DbgkpQueueMessage()`进行插入,此函数不仅是假消息插入核心,也是正常调试消息插入核心函数。

这就是在DbgkpPostFakeProcessCreateMessage中发送假线程过程,发送假dll也是在此函数中进行,原理类似。

### 0x1-3-2 DbgkpQueueMessage

函数声明如下

```c++
NTSTATUS
DbgkpQueueMessage (
    IN PEPROCESS Process,
    IN PETHREAD Thread,
    IN OUT PDBGKM_APIMSG ApiMsg,
    IN ULONG Flags,
    IN PDEBUG_OBJECT TargetDebugObject
    );
```

函数作用主要是

- 对于发送假消息(==本质是假消息调用此函数传入flags为NoWait,不用替换DebugObject==),直接操作TargetDebugObject。
- 对于需要等待的消息,取得Process.DebugPort,根据ApiMsg初始化DebugEvent,挂入DebugPort.EventList链表,KeWaitXXX(DebugEvent.ContinueEvent)等待

值得注意的是,此时的等待是被调试进程等待DebugEvent。而非调试进程等待,原因是如果是非NoWait消息,此时被调试进程一定有DebugPort,才可能产生这种消息,而且代表`DbgkpQueueMessage`调用者是被调试进程自己而不是调试进程在模拟假消息时候的调用,因此==此时的等待是被调试进程等待DebugEvent==

`KeWaitForSingleObject(&DebugEvent_1->ContinueEvent.Header, 0, 0, 0, 0i64);// 进行等待`

值得一提的是,`DbgkpQueueMessage`还被`DbgkpSendApiMessage`调用,而`DbgkpSendApiMessage`是调试的核心,所有和调试有关的信息最终会调用它。

IDA中交叉引用可以发现。`DbgkForwardException`异常处理也会调用它。

```assembly
Direction	Type	Address	Text
Up	p	DbgkPostModuleMessage+126	call    DbgkpSendApiMessage
Up	p	DbgkCreateThread+1BCAB8	call    DbgkpSendApiMessage
Up	p	DbgkCreateThread+1BCB42	call    DbgkpSendApiMessage
Up	p	DbgkMapViewOfSection+1BBB5A	call    DbgkpSendApiMessage
Up	p	DbgkUnMapViewOfSection+12C5FF	call    DbgkpSendApiMessage
Up	p	DbgkForwardException+11174E	call    DbgkpSendApiMessage
Up	p	DbgkCreateMinimalProcess+C6834	call    DbgkpSendApiMessage
Up	p	DbgkSendSystemDllMessages+2A0	call    DbgkpSendApiMessage
Down	p	DbgkCreateMinimalThread+82	call    DbgkpSendApiMessage
Down	p	DbgkExitProcess+96	call    DbgkpSendApiMessage
Down	p	DbgkExitThread+88	call    DbgkpSendApiMessage

```

复制ApiMsg到DebugEvent

```c++
CopyDApiMsgToDbkEvent:
  v15 = &DebugEvent_1->ApiMsg;
  DebugEvent_1->Process = Process_1;
  DebugEvent_1_1 = &DebugEvent_1->ApiMsg;
  DebugEvent_1->Thread = Thread_1;
  ApiMsg_2 = ApiMsg_1;
  v18 = 2i64;
  do                                            // 把ApiMsg复制过去
  {
    *(_OWORD *)DebugEvent_1_1->h = *(_OWORD *)ApiMsg_2->h;
    *(_OWORD *)&DebugEvent_1_1->h[16] = *(_OWORD *)&ApiMsg_2->h[16];
    *(_OWORD *)&DebugEvent_1_1->h[32] = *(_OWORD *)&ApiMsg_2->h[32];
    *(_OWORD *)&DebugEvent_1_1->u[3] = *(_OWORD *)&ApiMsg_2->u[3];
    *(_OWORD *)&DebugEvent_1_1->u[19] = *(_OWORD *)&ApiMsg_2->u[19];
    *(_OWORD *)&DebugEvent_1_1->u[35] = *(_OWORD *)&ApiMsg_2->u[35];
    *(_OWORD *)&DebugEvent_1_1->u[51] = *(_OWORD *)&ApiMsg_2->u[51];
    DebugEvent_1_1 = (_DBGKM_APIMSG *)((char *)DebugEvent_1_1 + 128);
    v19 = *(_OWORD *)&ApiMsg_2->u[67];
    ApiMsg_2 = (_DBGKM_APIMSG *)((char *)ApiMsg_2 + 128);
    *(_OWORD *)&DebugEvent_1_1[-1].u[211] = v19;
    --v18;
  }
  while ( v18 );
  *(_OWORD *)DebugEvent_1_1->h = *(_OWORD *)ApiMsg_2->h;
  _mm_storeu_si128((__m128i *)&DebugEvent_1->Cid, (__m128i)Thread_1->Cid);
```

操作DebugObject,插入双向链表

值得一提,如果是被调试进程主动调用此函数(需要等待),DebugObject==Process.DebugPort,否则,代表无需等待,DebugObject=TargetObject。

```c++
Tail = DebugObject_1->EventList.Blink;    // 这个算法是插到链表尾部
      if ( Tail->Flink != &DebugObject_1->EventList )
        __fastfail(3u);
      DebugEvent_1->EventList.Flink = &DebugObject_1->EventList;
      DebugEvent_1->EventList.Blink = Tail;
      Tail->Flink = &DebugEvent_1->EventList;
      DebugObject_1->EventList.Blink = &DebugEvent_1->EventList;
      if ( !bNoWait )
        KeSetEvent(&DebugObject_1->EventPresent, 0, 0);// 需要等待,设置一下DebugObject的位,当调试循环能改进行
//而我们发送假消息bNoWait是true,也就是不会KeSetEvent
      status = 0;
```

KeSetEvent作用是让调试进程的KeWait能改等待到,说明有消息需要处理,==即阻塞调试进程的线程。==

最后判断一下是否是需要等待的DebugEvent,需要等待,`KeWaitForSingleObject`,==即阻塞被调试进程的线程。==

```c++
KeReleaseGuardedMutex((ULONG_PTR)&DbgkpProcessDebugPortMutex);
    if ( status >= 0 )
    {
      KeWaitForSingleObject(&DebugEvent_1->ContinueEvent.Header, 0, 0, 0, 0i64);// 进行等待
      status = DebugEvent_1->Status;            // 注意,是被调试进程在这等待!
                                                // 等待的是DebugEvent的Event
                                                // 而DebugObject的Event则标志着有事件要进行处理
    }
```

### 0x1-3-3 DbgkpSetProcessDebugObject

**函数作用为**

- 设置被调试进程的DebugPort
- 遍历EventList,执行之前在DebugPort初始化的消息(==发送假消息只是初始化了这个结构体,并没有设置KeSetEvent,参见上文==)
- 清理无效的DebugEvent
- 再次遍历线程,双重保险,防止被调试进程又新建线程导致无法发送消息。

**函数声明如下**

```c
NTSTATUS
DbgkpSetProcessDebugObject (
    IN PEPROCESS Process,
    IN PDEBUG_OBJECT DebugObject,
    IN NTSTATUS MsgStatus,
    IN PETHREAD LastThread
    );
```

---

==以下函数代码来自WRK,非IDA逆出==

首先判断传入MsgStatus,这个值是`DbgkpPostFakeProcessCreateMessages`函数的返回值,标志这个函数是不是执行成功。

```c
 if (!NT_SUCCESS (MsgStatus)) { //这个是前面插入DebugObject List时候是否成功
        LastThread = NULL;
        Status = MsgStatus;
    } else {
        Status = STATUS_SUCCESS;
    }
```

设置被调试进程的DebugPort

```c
if (Process->DebugPort != NULL) {
                Status = STATUS_PORT_ALREADY_SET;
                break;
            }
            //
            // Assign the debug port to the process to pick up any new threads
            //
            Process->DebugPort = DebugObject;//设置调试对象
```

判断是否被调试进程新建线程,双重保险防止遗漏

```c
        while (1) {
            //
            // Acquire the debug port mutex so we know that any new threads will
            // have to wait to behind us.
            //
            GlobalHeld = TRUE;

            ExAcquireFastMutex (&DbgkpProcessDebugPortMutex);//获取

            //
            // If the port has been set then exit now.
            //
            if (Process->DebugPort != NULL) {
                Status = STATUS_PORT_ALREADY_SET;
                break;
            }
            //
            // Assign the debug port to the process to pick up any new threads
            //
            Process->DebugPort = DebugObject;//设置

            //
            // Reference the last thread so we can deref outside the lock
            //
            ObReferenceObject (LastThread);

            //
            // Search forward for new threads
            //
            Thread = PsGetNextProcessThread (Process, LastThread);//判断一下是否有新的线程,有的话再发假线程消息
            if (Thread != NULL) {

                //
                // Remove the debug port from the process as we are
                // about to drop the lock
                //
                Process->DebugPort = NULL;

                ExReleaseFastMutex (&DbgkpProcessDebugPortMutex);

                GlobalHeld = FALSE;

                ObDereferenceObject (LastThread);

                //
                // Queue any new thread messages and repeat.
                //

                Status = DbgkpPostFakeThreadMessages (Process,
                                                      DebugObject,
                                                      Thread,
                                                      &FirstThread,
                                                      &LastThread);
                if (!NT_SUCCESS (Status)) {
                    LastThread = NULL;
                    break;
                }
                ObDereferenceObject (FirstThread);
            } else {
                break;
            }
        }
 
```

遍历DebugObject->EventList链表,如果有值则` KeSetEvent (&DebugObject->EventsPresent, 0, FALSE);`

```c
for (Entry = DebugObject->EventList.Flink;//遍历DebugObject链表
         Entry != &DebugObject->EventList;
         ) {

        DebugEvent = CONTAINING_RECORD (Entry, DEBUG_EVENT, EventList);
        Entry = Entry->Flink;

        if ((DebugEvent->Flags&DEBUG_EVENT_INACTIVE) != 0 && DebugEvent->BackoutThread == ThisThread) {
            Thread = DebugEvent->Thread;

            //
            // If the thread has not been inserted by CreateThread yet then don't
            // create a handle. We skip system threads here also
            //
            if (NT_SUCCESS (Status) && Thread->GrantedAccess != 0 && !IS_SYSTEM_THREAD (Thread)) {
                //
                // If we could not acquire rundown protection on this
                // thread then we need to suppress its exit message.
                //
                if ((DebugEvent->Flags&DEBUG_EVENT_PROTECT_FAILED) != 0) {
                    PS_SET_BITS (&Thread->CrossThreadFlags,
                                 PS_CROSS_THREAD_FLAGS_SKIP_TERMINATION_MSG);
                    RemoveEntryList (&DebugEvent->EventList);
                    InsertTailList (&TempList, &DebugEvent->EventList);
                } else {
                    if (First) {//只有第一次进入才设置
                         DebugEvent->Flags &= ~DEBUG_EVENT_INACTIVE;
                        KeSetEvent (&DebugObject->EventsPresent, 0, FALSE);//设置DebugObject->Event,调试器的KeWait可以等待成功。
                        First = FALSE;
                    }
```

最后释放资源,清理无效DebugEvent

```c
 if (GlobalHeld) {
        ExReleaseFastMutex (&DbgkpProcessDebugPortMutex);//可以用于反调试 占用这个全局变量导致所有调试器无法调试,链接DebugPort
    }

    if (LastThread != NULL) {
        ObDereferenceObject (LastThread);
    }

    while (!IsListEmpty (&TempList)) {//清空无效DebugEvent
        Entry = RemoveHeadList (&TempList);
        DebugEvent = CONTAINING_RECORD (Entry, DEBUG_EVENT, EventList);
        DbgkpWakeTarget (DebugEvent);
    }
	return status;
```

# 0x2 调试器等待

## 0x2-1WaitForDebugEvent

在建立了Debugport调试关系之后,调试器需要创立一个while循环。

在循环中使用`WaitForDebugEvent()`进行等待,也就是等待DEBUG_OBJECT的Event。

```c++
while (1)
	{
		DEBUG_EVENT debugEvent = { 0 };
		if (WaitForDebugEvent(&debugEvent, -1))
```

在`WaitForDebugEvent()`中,首先会调用

```c++
do                                            // 也就是如果是用户APC或者Altered被唤醒 会一直让你等
  {
    do
      STATUS = DbgUiWaitStateChange(&WaitStateChange, WaitTime_1);
    while ( STATUS == 0x101 );                  // #define STATUS_ALERTED                   ((NTSTATUS)0x00000101L)
  }
  while ( STATUS == 0xC0 );                     // #define STATUS_USER_APC                  ((NTSTATUS)0x000000C0L)    // winnt
  if ( STATUS < 0 )
    goto Failed;
  if ( STATUS == 0x102 )                        // 等待时间完了
  {
    RtlSetLastWin32Error(0x79i64);              // #define STATUS_TIMEOUT                   ((NTSTATUS)0x00000102L)    // winnt
    return 0i64;
  }
```

进行等待,如果等待打断会进行判断,如果是ALERTED或者APC这种的打断,则继续等待,如果是等待时间TimeOut,返回错误。

在进行等待成功之后,会调用

```c++
STATUS = v4 ? (unsigned int)DbgUiConvertStateChangeStructureEx(&WaitStateChange, v3) : (unsigned int)DbgUiConvertStateChangeStructure(&WaitStateChange, v3);
  if ( STATUS < 0 )                             // 进行结构转换
                                                // 即把R0的WaitStateChnage转换成R3的DebugEvent
  {
Failed:
    BaseSetLastNTError((unsigned int)STATUS);
    return 0i64;
  }
```

是因为`WaitStateChange`结构是,而R3真正处理的是R3.DebugEvent,因此需要进行转换。

```c++
typedef struct _DBGUI_WAIT_STATE_CHANGE {
    DBG_STATE NewState;
    CLIENT_ID AppClientId;
    union {
        DBGKM_EXCEPTION Exception;
        DBGUI_CREATE_THREAD CreateThread;
        DBGUI_CREATE_PROCESS CreateProcessInfo;
        DBGKM_EXIT_THREAD ExitThread;
        DBGKM_EXIT_PROCESS ExitProcess;
        DBGKM_LOAD_DLL LoadDll;
        DBGKM_UNLOAD_DLL UnloadDll;
    } StateInfo;
```

在进行转换之后,判断dwDebugEventCode

```c++
dwDebugEventCode = DebugEvent_1->dwDebugEventCode;
  if ( DebugEvent_1->dwDebugEventCode != 1 )    // #define EXCEPTION_DEBUG_EVENT       1
                                                // #define CREATE_THREAD_DEBUG_EVENT   2
                                                // #define CREATE_PROCESS_DEBUG_EVENT  3
                                                // #define EXIT_THREAD_DEBUG_EVENT     4
                                                // #define EXIT_PROCESS_DEBUG_EVENT    5
                                                // #define LOAD_DLL_DEBUG_EVENT        6
                                                // #define UNLOAD_DLL_DEBUG_EVENT      7
                                                // #define OUTPUT_DEBUG_STRING_EVENT   8
                                                // #define RIP_EVENT                   9
  {
    if ( dwDebugEventCode == 2 )
    {
      hThread = DebugEvent_1->u.CreateThread.hThread;
    }
    else
    {
      if ( dwDebugEventCode != 3 )
      {
        if ( dwDebugEventCode == 4 )
        {
          MarkThreadHandle(DebugEvent_1->dwThreadId);// 标志进程退出
                                                // 这个结构如下
                                                // 在TEB的16A0位置
                                                // 0 LIST_ENTRY
                                                // 0x8 线程句柄
                                                // 0x10 进程句柄
                                                // 0x18 线程ID
                                                // 0x1C 进程ID
                                                // 0x20 是否退出
                                                // 这个就是用于方便调试器调试显示信息
        }
        else if ( dwDebugEventCode == 5 )
        {
          MarkThreadHandle(DebugEvent_1->dwThreadId);
          for ( i = NtCurrentTeb()->DbgSsReserved[0]; i; i = *(_QWORD *)i )
          {
            if ( *(_DWORD *)(i + 24) == DebugEvent_1->dwProcessId && !*(_DWORD *)(i + 28) )
            {
              *(_BYTE *)(i + 0x20) = 1;         // 标志所有线程退出
              return 1i64;
            }
          }
        }
        else if ( dwDebugEventCode != 6 && dwDebugEventCode != 7 && (dwDebugEventCode <= 7 || dwDebugEventCode > 9) )
        {
          return 0i64;
        }
        return 1i64;
      }                                         // 能走到这都是2 3
      SaveProcessHandle(DebugEvent_1->dwProcessId, DebugEvent_1->u.CreateProcessInfo.hProcess);// 如果是进程创建啥的 需要在那个单链表进行保存
      hThread = DebugEvent_1->u.CreateProcessInfo.hThread;
    }
    SaveThreadHandle(DebugEvent_1->dwProcessId, DebugEvent_1->dwThreadId, hThread);// 线程创建 也需要保存在单链表中
  }
  return 1i64;
}
```

即如果不是1,也就是`EXCEPTION_DEBUG_EVENT`,会判断进线程创建以及销毁。如果是,则会进行一些处理,具体是调用如下函数:

```c++
MarkThreadHandle(DebugEvent_1->dwThreadId);
SaveProcessHandle(DebugEvent_1->dwProcessId, DebugEvent_1->u.CreateProcessInfo.hProcess);// 如果是进程创建啥的 需要在那个单链表进行保存
SaveThreadHandle(DebugEvent_1->dwProcessId, DebugEvent_1->dwThreadId, hThread);
```

这些函数只有一个作用,就是把进程创建的线程 进程 保存在一个链表中。在TEB的`在TEB的16A0位置`

值得一提,这个链表的结构如下:

```c++
MarkThreadHandle(DebugEvent_1->dwThreadId);// 标志进程退出
                                                // 这个结构如下
                                                // 在TEB的16A0位置
                                                // 0 LIST_ENTRY
                                                // 0x8 线程句柄
                                                // 0x10 进程句柄
                                                // 0x18 线程ID
                                                // 0x1C 进程ID
                                                // 0x20 是否退出
                                                // 这个就是用于方便调试器调试显示信息
```

他唯一的作用就是==快速遍历当前调试进程的所有线程和进程==。

## 0x2-2 DbgUiWaitStateChange

这个函数是调试器等待机制的核心。

在WaitForDebugEvent中调用

```c++
STATUS = DbgUiWaitStateChange(&WaitStateChange, WaitTime_1);
```

```c++
__int64 __fastcall DbgUiWaitStateChange(__int64 pUnk, __int64 Waittime)
{
  __int64 v2; // rcx

  v2 = NtCurrentTeb()->DbgSsReserved[1];
  return ZwWaitForDebugEvent();                 // 等待对象就是调试对象的Event,时间就是传过来的
}
```

事实上,这个函数有三个参数,第一个参数就是hDebugObject了。

```c++
NTSTATUS
NtWaitForDebugEvent (
    IN HANDLE DebugObjectHandle,
    IN BOOLEAN Alertable,
    IN PLARGE_INTEGER Timeout OPTIONAL,
    OUT PDBGUI_WAIT_STATE_CHANGE WaitStateChange
    );
```

### 0x2-2-1 NtWaitForDebugEvent

调试器等待的内核实现。

其中核心代码如下

```c++
    while ( 1 )
    {
      status = KeWaitForSingleObject(&DebugObject_1->EventPresent.Header, 0, PreviousMode, v13, Timeout);// 等待PresentEvent
      if ( status < 0 || status == 0xC0 || (unsigned int)(status - 0x101) <= 1 )
        break;
      curEvent_1 = 0i64;
      ExAcquireFastMutex(&DebugObject_1->Mutex);// 能走到这 说明不是等待超时 而是有调试时间
      if ( DebugObject_1->Flags & 1 )
      {
        status = 0xC0000354;
      }
      else
      {
        ListHead = (_DEBUG_EVENT *)&DebugObject_1->EventList;
        for ( curEvent = (_DEBUG_EVENT *)DebugObject_1->EventList.Flink;
              curEvent != ListHead;
              curEvent = (_DEBUG_EVENT *)curEvent->EventList.Flink )
        {
          curEvent_1 = curEvent;
          flags = curEvent->Flags;
          if ( !(flags & 5) )                   // #define DEBUG_EVENT_INACTIVE        (0x04)  // The message is in inactive. It may be activated or deleted later
                                                // #define DEBUG_EVENT_READ            (0x01)  // Event had been seen by win32 app
          {
            bFind = 1;
            FirstDebugEvent = (_DEBUG_EVENT *)ListHead->EventList.Flink;
            if ( (_DEBUG_EVENT *)ListHead->EventList.Flink != curEvent )
            {
              while ( curEvent->ClientId.UniqueProcess != FirstDebugEvent->ClientId.UniqueProcess )
              {
                FirstDebugEvent = (_DEBUG_EVENT *)FirstDebugEvent->EventList.Flink;
                if ( FirstDebugEvent == curEvent )
                  goto LABEL_23;
              }
              curEvent->Flags = flags | 4;      // #define DEBUG_EVENT_INACTIVE        (0x04)  // The message is in inactive. It may be activated or deleted later
              curEvent->BackoutThread = 0i64;   // 一个DEBUG_PORT可以调试多个进程 这是再找有没有当前进程的DEBUG_EVENT
              bFind = 0;
            }
LABEL_23:
            if ( bFind )
              goto LABEL_27;
          }
        }
        if ( bFind )
        {
LABEL_27:
          Process = *(_OWORD *)&curEvent_1->Process;
          Thread = Process >> 64;
          *(_QWORD *)&SysTime.High2Time = Process;
          ObfReferenceObjectWithTag(Thread);
          ObfReferenceObjectWithTag(*(ULONG_PTR *)&SysTime.High2Time);
          DbgkpConvertKernelToUserStateChange((__int64)&WaitStateChange_2, (__int64)curEvent_1);// 根据EVENT去处理一下WaitStateChange
                                                // 需要参考WRK
          curEvent_1->Flags |= 1u;              // READ处理过
          goto LABEL_29;
        }
        KeResetEvent(&DebugObject_1->EventPresent);//设置等待
LABEL_29:
        status = 0;
      }
      KeReleaseGuardedMutex((ULONG_PTR)&DebugObject_1->Mutex);
      if ( status < 0 )
        break;
      if ( bFind )
      {                                         // 解锁
        DbgkpOpenHandles(&WaitStateChange_2, *(_QWORD *)&SysTime.High2Time, Thread);
        ObfDereferenceObjectWithTag(Thread);
        ObfDereferenceObjectWithTag(*(ULONG_PTR *)&SysTime.High2Time);
        break;
      }
      bFind = 0;
      if ( v25 < 0 )
      {
        v22 = MEMORY[0xFFFFF78000000014] - *(_QWORD *)&SysTime.LowPart + v25 < 0;
        v25 += MEMORY[0xFFFFF78000000014] - *(_QWORD *)&SysTime.LowPart;
        *(_QWORD *)&SysTime.LowPart = MEMORY[0xFFFFF78000000014];
        DebugObject_1 = DebugObject;
        if ( !v22 )
        {
          status = 258;
          break;
        }
      }
      v13 = Alertable;
    }
```

本质就是调用`KeWaitForSingleObject,直到被调试进程SetEvent之后才能往下走。

再找到要处理的Event之后,

` DbgkpConvertKernelToUserStateChange((__int64)&WaitStateChange_2, (__int64)curEvent_1);// 根据EVENT去处理一下WaitStateChange`去复制Event的内容到WaitStateChange,然后返回。

值得一提的是,==KeResetEvent完成了事件的等待处理,直到下一个KeSetEvent==

自此,调试器等待就完毕了。剩下的就是R3的处理了,即把等待获取的`WaitStateChange`变量转换成R3可识别的DEBUG_EVENT即可,上面也已经提到了。

# 0x3事件处理

 在调试器接受到事件之后,调用进行事件处理。这个函数本质是修改了位于DEBUG_OBJECT中的DEBUG_EVENT.ContinueEvent,让被调试进程中WaitSingleObject通信。所以进程调试是离不开这两个Event的。一个是DEBUG_EVENT的ContinueEvent,一个是DEBUG_OBJECT.PresentEvent。前者是被调试进程等待处理,后者是调试器等待消息。

```c++
ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, DBG_CONTINUE);
```

值得一提的是,调试器很大程度是基于异常处理的,但是调试器处理异常时,却不是使用类似SEH VEH等发送的CONTEXT,修改pContext值,然后返回R0修改的。调试器异常处理只需要返回1就代表此异常已经处理了。处理需要通过SetThreadContext来改变线程的寄存器的值。

在ContinueDebugEvent中,核心就是

`v5 = DbgUiContinue(&dwProcessId_1, dwContinueStatus);`

直接调用

```c++
__int64 __fastcall DbgUiContinue(__int64 pProcessId, unsigned int dwContinueStatus)
{
  return NtDebugContinue(NtCurrentTeb()->DbgSsReserved[1], pProcessId, dwContinueStatus);
}
```

## 0x3-1NtDebugContinue

函数声明:

```c++
NTSTATUS
NtDebugContinue (
    IN HANDLE DebugObjectHandle,
    IN PCLIENT_ID ClientId,
    IN NTSTATUS ContinueStatus
    );
```

其中核心代码如下

```c++
while ( 1 )
    {
      if ( DebugEvent->ClientId.UniqueProcess == ProcessId )
      {
        if ( GetEvent )                         // 先清空Event结点 在进行处理
        {
          DebugEvent->Flags &= 0xFFFFFFFB;      // 去掉4 INACTIVE
          KeSetEvent(&DebouObject->EventPresent, 0, 0);// 这个不是对调试对象发!而是对调试器发 这样我们调试循环立刻就会接收到消息
ListEmpty:
          KeReleaseGuardedMutex((ULONG_PTR)&DebouObject->Mutex);
          HalPutDmaAdapter(DebouObject);
          if ( !GetEvent )
            return 0xC000000D;
          if ( PerfGlobalGroupMask & 0x400000 )
            EtwTraceDebuggerEvent((__int64)DebugEvent_1->Process, (__int64)DebugEvent_1->Thread, 2);// 反调试?
          DebugEvent_1->ApiMsg.ReturnedStatus = dwContinueStatus_1;
          DebugEvent_1->Status = 0;
          DbgkpWakeTarget(DebugEvent_1);        // 他就是ResumeThread+设置Event.ContinueEvent
          return status;
        }
        if ( DebugEvent->ClientId.UniqueThread == ThreadId && DebugEvent->Flags & 1 )
        {
          v15 = DebugEvent->EventList.Flink;
          v16 = DebugEvent->EventList.Blink;
          if ( (_DEBUG_EVENT *)DebugEvent->EventList.Flink->Blink != DebugEvent
            || (_DEBUG_EVENT *)v16->Flink != DebugEvent )
          {
            __fastfail(3u);
          }
          v16->Flink = v15;                     // 摘除结点
          v15->Blink = v16;
          DebugEvent_1 = DebugEvent;
          GetEvent = 1;                         // 这个标志的意义是 while循环
                                                // 他一次只能处理一个调试Event
                                                // 但是while循环遍历整个Event链表
                                                // GetVent可以保证只有一个处理了,然后KeSetEvent
                                                // 让调试器赶紧去处理下一个
        }
      }
      DebugEvent = (_DEBUG_EVENT *)DebugEvent->EventList.Flink;
      if ( DebugEvent == (_DEBUG_EVENT *)&DebouObject->EventList )
        goto ListEmpty;
    }
```

==值得一提是他循环EventList的判断机制,他的判断机制是如果有超过一个Event挂在链表上，就去进行SetEvent,这个的作用是让R3的调试循环直接进行,可以节省时间==。

他是先去除结点,在进行判断是否为空,如果为空的话直接ListEmpty,就ret了。不会进行KeSetEvent了。

其中,` DbgkpWakeTarget(DebugEvent_1);`的作用就是唤醒进程,同时设置一下Event.ContinueEvent,使得被调试进程能够继续运行下去。函数实现如下

```c++
VOID
DbgkpWakeTarget (
    IN PDEBUG_EVENT DebugEvent
    )
{
    PETHREAD Thread;

    Thread = DebugEvent->Thread;

    if ((DebugEvent->Flags&DEBUG_EVENT_SUSPEND) != 0) {
        PsResumeThread (DebugEvent->Thread, NULL);
    }

    if (DebugEvent->Flags&DEBUG_EVENT_RELEASE) {
        ExReleaseRundownProtection (&Thread->RundownProtect);
    }

    //
    // If we have an actual thread waiting then wake it up else free the memory.
    //
    if ((DebugEvent->Flags&DEBUG_EVENT_NOWAIT) == 0) {
        KeSetEvent (&DebugEvent->ContinueEvent, 0, FALSE); // Wake up waiting process
    } else {
        DbgkpFreeDebugEvent (DebugEvent);
    }
}

```

先进性判断,Event.Flags是否是进程需要暂停,不需要Resume线程,继续判断Event.Flags是否需要等待,如果需要等待,那么SetEvent ContinueEvent,让被卡住的进程继续下去,不等待则直接清理Event内存和零化链表。

# 0x4被调试进程消息采集

调试器等待和事件处理本质上是调试器做得事情,对于被调试进程,需要在各种情况下进行消息收集,放到DEBUG_OBJECT的链表中。

其核心函数在第一节有,即

`DbgkpSendApiMessage()`调用`DbgkpQueueMessage()`将ApiMsg变成DEBUG_EVENT挂入链表,在`DbgkpQueueMessage()`中,包含了KeWaitForSingleObject进行等待Event.ContinueEvent。

## 0x4-1 DbgkpQueueMessage

函数定义如下

```c++
NTSTATUS
DbgkpQueueMessage (
    IN PEPROCESS Process,
    IN PETHREAD Thread,
    IN OUT PDBGKM_APIMSG ApiMsg,
    IN ULONG Flags,
    IN PDEBUG_OBJECT TargetDebugObject
    );
```



- 寻找DEBUG_PORT

对于NoWait的Event消息,DEBUG_PORT使用TargetDebugObject,==这是为了发送假消息做兼容==

对于需要等待的消息,DEBUG_PORT使用Process.DebugPort

```c++
if ( !(flags_1 & 2) ) 
  {
    DebugObject_1 = (_DEBUG_PORT *)Process_1->DebugPort;
```

flags定义

```c++
#define DEBUG_EVENT_READ            (0x01)  // Event had been seen by win32 app
#define DEBUG_EVENT_NOWAIT          (0x02)  // No waiter one this. Just free the pool
#define DEBUG_EVENT_INACTIVE        (0x04)  // The message is in inactive. It may be activated or deleted later
#define DEBUG_EVENT_RELEASE         (0x08)  // Release rundown protection on this thread
#define DEBUG_EVENT_PROTECT_FAILED  (0x10)  // Rundown protection failed to be acquired on this thread
#define DEBUG_EVENT_SUSPEND         (0x20)  // Resume thread on continue
```

- 复制ApiMsg到DEBUG_EVENT

```c++
ApiMsg_2 = ApiMsg_1;
  v18 = 2i64;
  do                                            // 把ApiMsg复制过去
  {
    *DebugEvent_1_1 = *(_OWORD *)ApiMsg_2->h;
    DebugEvent_1_1[1] = *(_OWORD *)&ApiMsg_2->h[16];
    DebugEvent_1_1[2] = *(_OWORD *)&ApiMsg_2->h[32];
    DebugEvent_1_1[3] = *(_OWORD *)&ApiMsg_2->u.Exception.ExceptionRecord.ExceptionCode;
    DebugEvent_1_1[4] = *((_OWORD *)&ApiMsg_2->u.UnloadDll + 1);
    DebugEvent_1_1[5] = *((_OWORD *)&ApiMsg_2->u.UnloadDll + 2);
    DebugEvent_1_1[6] = *((_OWORD *)&ApiMsg_2->u.UnloadDll + 3);
    DebugEvent_1_1 += 8;
    v19 = *((_OWORD *)&ApiMsg_2->u.UnloadDll + 4);
    ApiMsg_2 = (_DBGKM_APIMSG *)((char *)ApiMsg_2 + 128);
    *(DebugEvent_1_1 - 1) = v19;
    --v18;
  }
  while ( v18 );
```

- 对于需要等待的,进行KeWaitForSingleObject

```c++
KeWaitForSingleObject((_DISPATCHER_HEADER *)(DebugEvent_1 + 2), 0, 0, 0, 0i64);// 进行等待
      status = *((_DWORD *)DebugEvent_1 + 18);  // 注意,是被调试进程在这等待!
                                                // 等待的是DebugEvent的Event
                                                // 而DebugObject的Event则标志着有事件要进行处理
```

同时,KeSeventEvent来进行调试器可以等待成功

```c++
KeSetEvent(&DebugObject_1->EventPresent, 0, 0);// 需要等待,设置一下DebugObject的位,当调试循环能改进行
```

## 0x4-2收集API

收集API众多,最终会调用`DbgkpSendApiMessage`,收集API有

```c++
DbgkPostModuleMessage+126		call    DbgkpSendApiMessage
DbgkCreateThread+1BCAB8			call    DbgkpSendApiMessage
DbgkCreateThread+1BCB42			call    DbgkpSendApiMessage
DbgkMapViewOfSection+1BBB5A		call    DbgkpSendApiMessage
DbgkUnMapViewOfSection+12C5FF	call    DbgkpSendApiMessage
DbgkForwardException+11174E		call    DbgkpSendApiMessage
DbgkCreateMinimalProcess+C6834	call    DbgkpSendApiMessage
DbgkSendSystemDllMessages+2A0	call    DbgkpSendApiMessage
bgkCreateMinimalThread+82		call    DbgkpSendApiMessage
DbgkExitProcess+96				call    DbgkpSendApiMessage
DbgkExitThread+88				call    DbgkpSendApiMessage
```

这些收集API如创建线程收集API`DbgkCreateThread`这些API是在创建线程的必经之路上的。

这些函数会进行把信息变成DBGKM_APIMSG结构然后调用DbgkpSendApiMessage。

### 0x4-2-1 线程逃逸

```c++
    // If the create worked then notify the debugger.
    //
    if ((Thread->CrossThreadFlags&
         (PS_CROSS_THREAD_FLAGS_DEADTHREAD|PS_CROSS_THREAD_FLAGS_HIDEFROMDBG)) == 0) {
        DbgkCreateThread (Thread, StartContext);
    }
```

```c++
 if (DebugException) {
        if (PsGetCurrentThread()->CrossThreadFlags&PS_CROSS_THREAD_FLAGS_HIDEFROMDBG) {
            Port = NULL;
        } else {
            Port = Process->DebugPort;
        }
        LpcPort = FALSE;
    } else {
        Port = Process->ExceptionPort;
        m.h.u2.ZeroInit = LPC_EXCEPTION;
        LpcPort = TRUE;
    }
    //
    // If the destination LPC port address is NULL, then return FALSE.
    //

    if (Port == NULL) {
        return FALSE;
    }

    if (LpcPort) {
        st = DbgkpSendApiMessageLpc(&m,Port,DebugException);
    } else {
        st = DbgkpSendApiMessage(&m,DebugException);
    }
```

在进行收集时,如果线程的HideFromDebugger位被置位,那么就不会进行收集信息了,俗称线程逃逸。

调用NtSetInfomationThread中有个ThreadHideFromDebugger(14号功能),就会频闭调试器。

# 0x5 调试原理

## 0x4-1 Int3断点

本质上,Int3断点就是往一个地址写入CC,即int 3;在线程执行这个地方时,会进入3号中断。即

与所有的陷阱门最后分发基本一致

```c++
mov     ecx, 80000003h
mov     edx, 1
mov     r8, [rbp+0E8h]  ; 80+E8==RIP
dec     r8              ; RIP-1
mov     r9d, 0
call    KiExceptionDispatch
nop
retn
```

但是RIP是-1的。

在`KiDispatchException`进行异常派发时,调用

```C
DbgkForwardException(ExceptionRecord_1,1,0);// 调用异常消息采集
```

如果处理,则代表调试器处理。不用在进行异常分发。

### 0x4-1-1 DbgkForwardException

函数声明如下

```c++
DECLSPEC_NOINLINE
BOOLEAN
DbgkForwardException(
    IN PEXCEPTION_RECORD ExceptionRecord,
    IN BOOLEAN DebugException,
    IN BOOLEAN SecondChance
    );
```

函数首先

- 判断是否隐藏调试器的线程

```c++
if ( *(_DWORD *)((char *)&KeGetCurrentThread()[1]._union_100.SwapListEntry + 8) & 4 )// 这个是HideFromDebugger
      DebugPort = 0i64;                         // 如果线程逃逸 那么就是0
    else
      DebugPort = (_DEBUG_PORT *)Process->DebugPort;
    isLpc = 0;
```

- 初始化ApiMsg变量

```c++
 KeCopyExceptionRecord(&ApiMsg.u, ExRecord_1); // 复制到ApiMsg
```

- 调用SendApiMessage

```c++
status = DbgkpSendApiMessage(Process, DebugException_1 != 0, &ApiMsg);
```

- 根据status判断是否调试器处理了

```C
 if ( status < 0 )                             // 调试器没有处理
    return 0;
return 1;
```

## 0x4-2单步与硬件断点

单步异常是TF位置位,会触发异常1号。从而一系列流程。

和int 1效果是一样的。

通过Dr寄存器可以区分硬断和单步断点。Dr6=0xf用于区分是否是硬件还是单步调试。

==值得一提的是,对DR寄存器的操作都是Spuerviosr操作,设置Dr寄存器统统依靠API实现。==

==另外,DR7 中G 和L位,在Windows下通过API设置全局的硬件断点是无效的,即DR7中如果G位有值,API会忽略==。



## 0x4-3 内存断点



就是页面异常。值得一提的是,一种可以用于无痕Hook的内存断点可以不依赖重定位。

但是效率极其低下。这些是OD等进程实现重复内存Hook的思路

思路如下:

> 首先对某个页面进行Hook,调试或VEH/SEH接管之后,被中断,通过某些标志位进行判断是否是页面异常+在页面异常Hook范围内。
>
> 进行判断,如果就是Hook地址,进行Hook操作
>
> 如果不是,恢复页面异常,设置TF单步异常位,判断是否是要Hook地址,如果不是,设置页面异常。如此迭代,直到暂停于要Hook的地方为止。

