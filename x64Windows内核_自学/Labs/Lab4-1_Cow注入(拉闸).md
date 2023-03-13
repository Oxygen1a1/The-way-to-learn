# COW注入

实际上就是Cpoy on write的注入;

思路很简单,就是利用漏洞

BE 注册LoadImage回调,通知R3 BEservice;调用CreateFile,来读取文件,读取完之后

但是BEservice毕竟是R3的进程,因此可以通过简单地Hook CreateFile;

来达到目的,让他CreateFile读的是ntdll;

而COW就是关掉WINDOWS的写拷贝机制,让他全局Hook CreateFile;

这样即使驱动不加载,只要调用CreateFile就会注入;

