# C#的面向对象

C#的面向对象也就是OOP是在面向过程编程发展起来的；

面向对象可以描述世界中一切事物;而代码运行的结果就是各个对象相互作用的结果;

而在C#中一切都是对象,一切一切....

## 对象与类

类和对象是息息相关的,也就是表示对象的总和;

而类实例化(可以理解初始化)之后就变成了类;

和C++一样,可以使用new 来实例化一个类

### 类、实例、对象的关系

![image-20230312172540218](./assets/image-20230312172540218.png)

所以面向对象核心就是如何定义类,而定义类就是class 类名{}

## static非static的成员函数

这一点和C++很像,非static就是有this,C#中也可以用this,只不过是C++中是指针,而C#直接用.运算即可;

一旦加了static这个修饰符,也就代表只能操作static对象,也就是说假如此时定义一个类实例对象,

改对象这个static函数无法使用,只要类.实例函数才能使用;

```C#
public static double GetDistance(Point p1, Point p2)
            {//这个代表一句话返回
                double d = Math.Pow(p1.x - p2.x, 2) + Math.Pow(p1.y - p2.y, 2);
                return Math.Pow(d, 0.5);
            
            }
```

如上图,只能用

`Point.GetInstance()`而不是`p.GetInstance()`这样使用;值得一提的是，C#中类中任何任何成员,函数都必须具备==访问修饰符,即private,public等==,一行一个;

## C#的Ctor

和C++类似,C#也有构造函数,也支持重载;

```c#
            public Point() { x = 0;y = 0; }
            public Point(int x,int y) { this.x = x;this.y = y; }
```

这样就是ctor;

而C#的Ctor初始化有些不同,这是因为,C#的所有对象都是new出来的,也无需考虑delete等问题;

假如要new数组,就直接string[] words=new string[];==一切都是动态的,不需要释放,不需要考虑数组大小问题==

想要new一个类,就直接class obj=new class();而这个()里面就可以使用构造函数的参数了;

```C
Point p1 = new Point(0,0);
```

## set、get(自动属性)

可谓是C#让我最眼前一新的功能了;

这个功能可以用于那些private但是又必须获取的成员变量,比如

```C#
class Point{
    
    public int X{get;set;}
    private int x;
    private int y;
}

```

其中的`public int X{get;set;}`就是默认的get、set函数,这就相当于是有三个成员,而大X可以直接用于直接进行赋值;

但是这看起来似乎又没什么用,但是他又另一个用处,就是可以自定义X这个函数的set、get;

比如这样

```C#
public class Point{
    
    public int X{
        get{
         return this.x;   
        }
        set{
            this.x=value;
        }
    }
    private int x;
}

```

这样可以把X和x关联起来,这样使用大X其实就是使用小x,而value是C#自带的属于set里面的关键字;

## readonly和const

其实就是Access限定符不一样,而readonly和const的区别就是readonly代表每个类实例后的对象不一样,但是const都开始就确定了,而readonly一般是在==构造函数中初始化的,此后再也不能修改==;

## 关于索引

### 类中重载索引

C#的索引灵活多变,首先,它可以在类中重载索引,重载如下,有点像C++的重载索引运算符

```c#
            public string this[int index]
            {
                get
                {
                    return words[index];
                }
                set
                {
                    words[index] = value;

                }
            }
```

### 其他的索引运用

总之和C差不多,new出来一个[]之后,0开始,但是C#配备了倒数第几个,^1代表倒数第一个,以此类推;

当然,C#还有一个Range,用0..3表示,如下

```C#
var list = words[0..3];
```

需要注意的是,这里的var就相当于是C++的==auto==,等价于==string[] list=words[0..3]==;这里需要特别注意,C#的数组和C++/C区别就是C#数组在类型后,而C++在名称后;



## partial类

partial就是可以把一个类拆开写,如下

```C#
public partial class Point{
    
    private int x;
    
}

public partial class Point{
    
    private int y;
}
```

等价于

```c#
public partial class Point{
    
    private int x;
    private int y;
    
}
```

这样做的好处是可以把class Point分为不同的cs文件,这样用来分开文件可以更明确;不同功能但是同一个类可以分开文件写;

