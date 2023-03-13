# PteHook过ObCallBack回调^*^

通常,游戏都会调用ObCall来进行保护,这让OpenProcess的时候无法打开正常权限的句柄。

而众所周知,句柄只是一个在进程私有句柄表的一个索引，在内核需要通过ObReferenceObjectByHandle来进行转换。

因此,如果能Hook Obref则可以一劳永逸

在win7以及win10 14393版本,所有权限检查通通调用**ObRefXXwithtag**

而更高版本,ObpRefXXWithTag才是最终调用。而Hook方法很简单

**使用Pte隔离之后,修改DesriedAccess或者是AccessMode**

```c++
NTSTATUS MyObpReferenceObjectByHandleWithTag(HANDLE Handle, ACCESS_MASK DesiredAccess, POBJECT_TYPE ObjectType, KPROCESSOR_MODE AccessMode, ULONG Tag, PVOID* Object, POBJECT_HANDLE_INFORMATION HandleInformation,PVOID Unk) {
	UNREFERENCED_PARAMETER(AccessMode);
	UNREFERENCED_PARAMETER(DesiredAccess);

	return g_OriObpReferenceObjectByHandleWithTag(Handle, 0, ObjectType, 0, Tag, Object, HandleInformation,Unk);
}

```

## 缺陷

毛泽东说过:"任何反动派都是纸老虎",我以为,任何不能用于实战的东西都是纸老虎。

这个HOOK亦是如此,PteHook及其不稳定，而且似乎Hook这个函数会被ACE BE 强制蓝屏。

而且观感上很不好,数据时有时无,找不到原因。