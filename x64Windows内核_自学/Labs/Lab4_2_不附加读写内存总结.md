# 不附加读写内存的方法

通常,不附加读写应用场景是FPS,需要大量挂靠读写的场景。

而大量挂靠会被检测,这是因为可以通过遍历线程,来查询到现在是否挂靠(即附加)了进程。

而常用的读写函数,比如ZwRead/Write,MmCpoy等,都是要附加,来切换CR3,进行读写的。

通常,有两种方向来避免附加

- ==根据Cr3,读写物理地址==

  

  **1.即根据Cr3+进程的地址,根据线性地址进行分页读写**

  ​	模仿4级分页,使用**PhysicalMemory**这个节区对象读写

  ​	想要那个线性地址,直接在PTE_BASE里面查找出来PTE项,然后再次MmIoSpace或者别的即可。

  ​	**但是不知道效率如何,而且BE EAC会检测,物理内存节区对象映射的内存在VAD中过于明显**

  2. **MmCpoyMemory根据CR3读写物理内存**

     2. 本质上也是一种模仿四级分页进行读写的方式,经测试

        **APEX是不查的,但是似乎某些游戏会查。**

- **伪造EPROCESS**

申请非分页内存,把其他非游戏进程EPROCESS复制一份,把EPROCESS的Cr3给替换。

总之,思路是这样。

而替换EPROCESS,其实只需要替换一个地方即可，即KPROCESS的0x28处的cr3,

至于KPTI,双页表,均不考虑。

因为本质上这个还是挂靠读写,只不过是挂靠自己伪造的假进程来读写

而KiAttchProcess在加了KPTI之后的代码如下

```c++
new_cr3 = attch_process->Pcb.DirectoryTableBase;// KiLoadDirectoryTableBase
  if ( KiKvaShadow )                            // KPTI开启
  {
    shadow_cr3 = attch_process->Pcb.DirectoryTableBase;
    if ( new_cr3 & 2 )                          // KernelCr3 如果是内核Cr3 那就不会使TLB失效
      shadow_cr3 = new_cr3 | 0x8000000000000000ui64;// 最高位,即不需要刷新TLB
    __writegsqword(0x9000u, shadow_cr3);        // KernelDirectoryTableBase
    KiSetAddressPolicy((unsigned __int8)attch_process->Pcb.AddressPolicy);
  }
  result = (unsigned int)HvlEnlightenments;     // 是否开启Hyper-V
  if ( HvlEnlightenments & 1 )
    result = HvlSwitchVirtualAddressSpace(new_cr3);// Hv切换Cr3
  else
    __writecr3(new_cr3);
  if ( !KiFlushPcid && KiKvaShadow )            // 不支持自动刷新pcid 并且KPTI开启
  {
    cr4 = __readcr4();
    if ( cr4 & 0x20080 )
    {
      result = cr4 ^ 0x80;
      __writecr4(cr4 ^ 0x80);
      __writecr4(cr4);
    }
    else
    {
      result = __readcr3();
      __writecr3(result);
    }
  }
```

即他切换Cr3肯定是切内核的,如果切用户CR3,因为双页表用户CR3没有内核空间,直接三次错误。

而这些也有些有意思的代码。

```C
shadow_cr3 = new_cr3 | 0x8000000000000000ui64;// 最高位,即不需要刷新TLB
    __writegsqword(0x9000u, shadow_cr3);        // KernelDirectoryTableBase
```

比如切换cr3，置位最高位,让他不会刷新TLB;

2. 

