# 键盘过滤

与串口过滤相似,键盘的过滤也是通过Device_object来进行的附加原设备;

一般来说,键盘过滤的设备对象也是有名字的,叫做"kbdcalsss0",当然,如果键盘更多的话,会有更多;

## 如何Attch Device

对于键盘的过滤设备附加,有两个函数

- IoAttchDevice

- IoAttchDeviceToDeviceStack

第一个是要知道原始设备对象的名字,返回的是==lower dev==,第二个需要原来的设备对象;二者各有好处,因此这里也可以用两种方法;

### IoAttchDevice

```c++
	//接下来使用缓冲区 其实kbd一般就是用systembuffer 也就是BUFFERED
	ftl_dev->Flags |= DO_BUFFERED_IO;
	//代表着开始
	ftl_dev->Flags &= ~DO_DEVICE_INITIALIZING;
	RtlSecureZeroMemory(ftl_dev->DeviceExtension, sizeof(KBD_EXT_INFO));
	//ftl_dev->DeviceType = next_dev->DeviceType;
	//因为有名字 直接用IoAttchDevice
	PDEVICE_OBJECT next_dev{ 0 };
	status = IoAttachDevice(ftl_dev, &kbd_name, &next_dev);
```

这里需要注意的就是flags其实只需要设置两个即可,一个就是DO_BUFFERED_IO;第二个是`ftl_dev->Flags &= ~DO_DEVICE_INITIALIZING;`这个代表着设备正式开始执行;

事实上,如果填DO_DIRECT_IO,则直接在UserBuffer中找,DO_POWER_PAGABLE则是MdlAddress映射;

### IoAttchDeviceToDeviceStack

用这个附加设备更麻烦些,需要先找到键盘设备对象;一般找方法是通过

```c++
EXTERN_C NTSTATUS ObReferenceObjectByName(PUNICODE_STRING ObjectName,
	ULONG Attributes,
	PACCESS_STATE AccessState,
	ACCESS_MASK DesiredAccess,
	POBJECT_TYPE ObjectType,
	KPROCESSOR_MODE AccessMode,
	PVOID ParseContext,
	PVOID* Object);
```

而ObjectType填`EXTERN_C POBJECT_TYPE* IoDriverObjectType;`这些都是导出但是wdm中没有定义;

而名字填`#define KBD_DRIVER_NAME  L"\\Driver\\Kbdclass"`;

可以看到,这里找到的是驱动对象,而找到键盘设备对象的方法就是遍历这个驱动对象的Device链表;

```c++
auto cur_dev = kbd_drv_obj->DeviceObject;
	PDEVICE_OBJECT ftl_dev{ 0 };
	while (cur_dev) {
		status = IoCreateDevice(drv_obj,
			sizeof(DEV_EXT_INFO),//用于附加信息,比如可以把设备栈的下一个给附加上
			0,
			cur_dev->DeviceType,
			cur_dev->Characteristics,
			0,
			&ftl_dev
		);

		//注意,返回的dev和target dev有时候不一样,返回的一定是之前位于最顶端的
		//第二个参数你可以认为只要在设备栈上,就可以
		auto next_dev = IoAttachDeviceToDeviceStack(ftl_dev, cur_dev);
```

## next_dev存在哪里?

在派遣函数处理中,需要IoCallDriver,第一个就是设备栈的下一个设备,而上面调用的那两个函数都是可以返回之前顶层的设备栈;

这里可以使用DeviceObject->DeviceExtension来保存,只需要在CreateDevice加上这个大小就可以了;

## Read派遣函数

Read派遣被调用就代表csrss的系统线程发送了一个请求,需要读取键盘端口上面的扫描码;

但是不一定键盘按下,因此存在一个==异步==现象,这个时候如何获取当前Read的IRP最终获取到的键盘按键呢?

这里需要一个叫做这个的函数

```c++
VOID
IoSetCompletionRoutine(
    _In_ PIRP Irp,
    _In_opt_ PIO_COMPLETION_ROUTINE CompletionRoutine,
    _In_opt_ __drv_aliasesMem PVOID Context,
    _In_ BOOLEAN InvokeOnSuccess,
    _In_ BOOLEAN InvokeOnError,
    _In_ BOOLEAN InvokeOnCancel
    );
```

它可以设置一个回调,让IRP结束后,可以走回调,这个时候可以在IRP中读取相关信息;

```c++
NTSTATUS dis_func_read(PDEVICE_OBJECT dev, PIRP irp) {
	auto ext = (PKBD_EXT_INFO)dev->DeviceExtension;
	auto next_dev = ext->next_dev;
	IoCopyCurrentIrpStackLocationToNext(irp);

	//安装return回调
	IoSetCompletionRoutine(irp, read_routine, 0, 1, 1, 1);
	g_pending_count++;
	//IoSkipCurrentIrpStackLocation(irp);
	return IoCallDriver(next_dev, irp);
}
```

## 如何结束

考虑如下情况,当Read IRP被执行,安装了CompletionRoutine,这个时候如果卸载了驱动,等到下次按键盘时,会直接产生BSOD;

因为这个时候需要确保所有的READ IRP的完成回调已经执行完;

这里采取一个非常简单的解决方法,那就是设置一个全局变量;叫做pending_count;

一旦IRP READ进入,+1;而IRP READ 完成回调完成-1;

因此结束进程可以这样写

IoDetachDevice(next_dev);
```C++
while (g_pending_count) {
	LARGE_INTEGER interval = { 0 };
	interval.QuadPart = -10 * 1000 * 1000;
	KeDelayExecutionThread(KernelMode, FALSE, &interval);
}

IoDeleteDevice(ftl_dev);
DbgPrintEx(77, 0, "[+]drv unload success\r\n");
```

## Read完成时的回调写法

在Read完成时,会进入之前设置的完成回调,这个时候如果想要读取正确的键盘,需要按照一定的结构读取;

参考[此链接](https://learn.microsoft.com/zh-cn/windows/win32/api/ntddkbd/ns-ntddkbd-keyboard_input_data?redirectedfrom=MSDN)查看结构

直接设置了BUFFERED_IO,所以在SystemBuffer中查找;

长度同样在IRP中查找,来确定这个结构的连续的长度;

```c
typedef struct _KEYBOARD_INPUT_DATA {
	USHORT UnitId;
	USHORT MakeCode;//scan code
	USHORT Flags;
	USHORT Reserved;
	ULONG  ExtraInformation;
} KEYBOARD_INPUT_DATA, * PKEYBOARD_INPUT_DATA;
```

而flags代表如下

```c++
char* keyflag[4] = { "keydown","keyup","e0","e1" };
```

因此遍历即可

```c++
for (int i = 0; i < buf_len; i += sizeof(KEYBOARD_INPUT_DATA));
		DbgPrintEx(77, 0, "[+]scan code->0x%x and state is %s\r\n", kbd_str->MakeCode, keyflag[kbd_str->Flags]);
```

这样即可达到遍历按键过滤的目的;当然,可以改变这个缓冲区的相关信息,从而达到过滤;

