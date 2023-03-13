# 串口过滤

## 过滤的概念

简而言之,就是在Windows已有的内核层中，添加新的**"Flter"**层,不影响上层和下层接口的前提下;事实上,Windows提供了很多过滤设施,比如==串口,键鼠,文件,网络==;

事实上,Windows正常运转重大原因就是因为外部有很多这种IO设备,可以简单地抽象理解为Win为每个这种设备都抽象做了一个叫做**设备对象(Device Object)**的东西,每个真实的设备IO,都绑定了一个最原始的设备对象;

在驱动编程通信中,最常见的是使用设备对象进行通信,事实上,就是在编写驱动的设备对象时,该驱动的设备对象绑定(**Attch**)了某些真实的IO设备,这样就形成了过滤,从而达到R3进程使用CreateFile、ReadFile时,能够先到自己的驱动的设备对象的MajorFunc里面;

## 设备附加

### IoAttchDevice

而上面的例子是一个特殊的例子,用于R3/R0通信;在过滤驱动中,依旧是需要自己创建一个设备对象,然后将其Attch到所要过滤的设备对象上面。这样自己的设备对象就会在**整个设备栈的最顶端,来接受过滤数据**,常见的设备附加有以下函数:

```c++
NTSTATUS
IoAttachDevice(
    _In_ _When_(return==0, __drv_aliasesMem)
    PDEVICE_OBJECT SourceDevice,
    _In_  PUNICODE_STRING TargetDevice,
    _Out_ PDEVICE_OBJECT *AttachedDevice
    );
```

`IoAttachDevice()`第一个参数就是自己提供的要绑定的设备对象,第二个是一个UNICODE_STRING,这里提供绑定的设备对象的名字,当然,有的设备没名字,所以不可以用这个进行附加。最后一个是返回的。前文提到**设备栈**概念,即肯定有其他驱动装了这个设备的过滤,而此时又有新的驱动安装附加,那么就形成设备栈。而这个返回的则是本驱动未附加之前的设备栈最顶端的设备;

这是因为,在过滤函数中,我们需要指定,是否还需要把**IRP**给发送到下一个设备;如果想要发送给下一个设备,那必须调用`IoCallDriver`来指导一个设备对象,因此为了不打乱原来的设备栈顺序,需要保存返回的这个设备;

### IoAttchDeviceToStackSafe

```c++
NTSTATUS
IoAttachDeviceToDeviceStackSafe(
    _In_  PDEVICE_OBJECT SourceDevice,
    _In_  PDEVICE_OBJECT TargetDevice,
    _Outptr_ PDEVICE_OBJECT *AttachedToDeviceObject
    );
```

这个函数更加适用,这是因为第二个参数,他传递是设备对象而不是设备名称,这样就可以附加没有名字的设备了;

## ftler设备的创建

正如创建设备对象通信那样,使用`IoCreateDevice`和`IoDeleteDevice`创建和删除;

而设备对象的创建,和通信不太一样的地方是一些属性必须和源设备一样;下面给出例子

```c++
	if(oldobj->Flags & DO_BUFFERED_IO)
		(*fltobj)->Flags |= DO_BUFFERED_IO;
	if(oldobj->Flags & DO_DIRECT_IO)
		(*fltobj)->Flags |= DO_DIRECT_IO;
	if(oldobj->Flags & DO_BUFFERED_IO)
		(*fltobj)->Flags |= DO_BUFFERED_IO;
	if(oldobj->Characteristics & FILE_DEVICE_SECURE_OPEN)
		(*fltobj)->Characteristics |= FILE_DEVICE_SECURE_OPEN;
	(*fltobj)->Flags |=  DO_POWER_PAGABLE;
	// 设置这个设备已经启动。
	(*fltobj)->Flags = (*fltobj)->Flags & ~DO_DEVICE_INITIALIZING;

```

## 源设备的寻找

因为本章是串口过滤,有设备的名字,根据设备名字来寻找设备使用如下函数

```c++
NTSTATUS
IoGetDeviceObjectPointer(
    _In_  PUNICODE_STRING ObjectName,
    _In_  ACCESS_MASK DesiredAccess,
    _Out_ PFILE_OBJECT *FileObject,
    _Out_ PDEVICE_OBJECT *DeviceObject
    );
```

这里需要注意的点有两点

- DesiredAcess填FILE_ALL_ACCESS即可
- FileObject一旦得到,立刻ObDef

在得到源设备的时候,便可以用IoAttchDeviceToStackSafe进行设备附加了;

## 派遣函数的处理

再附加设备之后,一般这样做

```C++
for (int i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++) {
	//所有的MajorFunc都一样
	drv_object->MajorFunction[i] = ccp_disp_func;

}
```

这样可以在ccp_disp_func这个派遣函数中统一处理;

在本书例子中,只处理了电源的派遣和写请求

在派遣函数(IRP,DEVICE)中

```c++
auto stack = IoGetCurrentIrpStackLocation(irp);


	for (int i = 0; i < MAX_COM_ID_COUNT; i++) {

		if (g_flt_dev[i] == dev_obj) {XXX}
    }

```

首先要验证,是否是我们已经存好的ftl设备,如果不是，那可能就是出问题了,所以统一这样处理,==当然处理了这个IRP也可以这样写==;

```c++
//不在自己的设备里面 有问题
	irp->IoStatus.Information = 0;
	irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
```

而我们根据获取的stack,找到IRP_MJ_XXX,最后处理如下:

```c++
//是我们的设备
			if (stack->MajorFunction == IRP_MJ_POWER) {
				//电源相关,一律放行
				PoStartNextPowerIrp(irp);
				IoSkipCurrentIrpStackLocation(irp);
				return PoCallDriver(g_next_dev[i],irp);
			}
			if (stack->MajorFunction == IRP_MJ_WRITE) {
				//打印下
				unsigned char* buf = 0;
				//读写的缓冲区一般位于3个指针中,哪个有用哪个
				ULONG len = stack->Parameters.Write.Length;
				if (irp->MdlAddress != 0) {

					buf = (unsigned char*)MmGetSystemAddressForMdlSafe(irp->MdlAddress, NormalPagePriority);
				}
				else if (irp->UserBuffer != 0) {

					buf = (unsigned char*)irp->UserBuffer;
				}
				else {
					buf = (unsigned char*)irp->AssociatedIrp.SystemBuffer;

				}

				//打印
				for (unsigned int j = 0; j < len; j++) {

					DbgPrintEx(77, 0, "[+]comcap:send data:->0x%x\r\n", buf[j]);

				}


				// 这些请求直接下发执行即可。我们并不禁止或者改变它。
				IoSkipCurrentIrpStackLocation(irp);
				return IoCallDriver(g_next_dev[i], irp);
			}

			//其他一律下发处理
			IoSkipCurrentIrpStackLocation(irp);
			return IoCallDriver(g_next_dev[i], irp);
```

值得注意的是首先是电源的处理,不太一样和其他的;

然后是我们拦截了以下写处理,而写操作的指针一般位于三个地方,分别是MdlAddress,UserBuffer,或者说SystemBuffer;

长度则位于`ULONG len = stack->Parameters.Write.Length;`这个里面.

然后直接这样即可传到下个设备处理;

```c++
IoSkipCurrentIrpStackLocation(irp);
return IoCallDriver(g_next_dev[i], irp);
```

如果直接完成请求,则使用`IoCompleteRequest`来完成请求,正如R0/R3通信那样;

## 动态卸载

在动态卸载时候,有可能碰到此时IRP正在被自己的派遣函数处理,这个时候是卸载不掉的;

采用延时卸载的方法,如下:

```c++
void ccpUnload(PDRIVER_OBJECT drv)
{
	ULONG i;
	LARGE_INTEGER interval;

	// 首先解除绑定
	for(i=0;i<CCP_MAX_COM_ID;i++)
	{
		if(s_nextobj[i] != NULL)
			IoDetachDevice(s_nextobj[i]);
	}

	// 睡眠5秒。等待所有irp处理结束
	interval.QuadPart = (5*1000 * DELAY_ONE_MILLISECOND);		
	KeDelayExecutionThread(KernelMode,FALSE,&interval);

	// 删除这些设备
	for(i=0;i<CCP_MAX_COM_ID;i++)
	{
		if(s_fltobj[i] != NULL)
			IoDeleteDevice(s_fltobj[i]);
	}
}
```

先使用`IoDetachDevice`,但是这样不一定卸载成功,但是一旦用了Detach,就再也不会进入我们的派遣了,所以5秒后,再次删除;

所以是先detach,在delete;这是最好的;