# 数据权限控制

v2.0.0

作者：**wenyu** wenyu7980@163.com

> 该项目为Maven项目，同时也是Spring stater，是基于Spring AOP开发的一个数据权限控制库。

### 什么是数据权限

权限控制一般是分为两种：

+ 针对接口的权限控制

  > 这种权限控制应用的比较广泛，例如RBAC，有很多的库可以使用，比如Shiro，Spring Security等等。

+ 针对数据的权限控制

  > 这种权限控制并没有很多的库可以使用，原因是这种控制是和业务相关联的，不能和业务很好的解耦，所以，需要嵌入到代码中。

这两种权限控制的区别：

> 接口权限控制是相同类型的数据，只要你有这个权限就一视同仁可以操作。
>
> 数据权限控制是即使是相同类型的数据，也要判断你是不是对该数据有操作权限。业务系统中是经常要用到的。



### 库使用简介

#### 核心注解

+ EnableDataPermit

  > 触发库注入

+ Permit

  > 属性注解
  >
  > 上级资源，可以用在属性上，同时也可以配合PermitSuperiors使用。
  >
  > 在属性上使用时，names不用赋值。
  >
  > 如果被注解的属性，通过PermitConfig.isPrimitive检查为true的clazz必须赋值。
  >
  > **clazz** 关联数据查询服务类
  >
  > **names** 类上注解时，复合key时使用
  >
  > **dynamic**
  >
  > ​	动态关联数据查询服务类
  >
  > ​	由属性决定关联服务类
  >
  > ​	该属性的类型必须是{PermitDynamicType 的子类
  >
  > **root**
  >
  > ​	判断是否是根校验
  >
  > ​	如果是根校验会调用PermitConfig#checkPermit(Object, Permit)
  >
  > **type** 根校验的辅助属性

+ Permits

  > 类注解
  >
  > 配合Permit使用

+ PermitMethod

  > 方法注解
  >
  > 需要权限校验的方法上，方法返回值只能是none or one
  >
  > **message** 权限不足时错误信息

#### 核心接口

+ Permittable

  > 数据获取接口，上级资源校验且上级资源的PermitConfig::isPrimitive为true时，需要通过该接口获取上级资源数据
  >
  > ```java
  > public interface Permittable<T, ID> {
  >     /**
  >      * 类型
  >      * @return
  >      */
  >     default Class<? extends Permittable> type() {
  >         return this.getClass();
  >     }
  > 
  >     /**
  >      * 通过id获取数据
  >      * @param id
  >      * @return
  >      */
  >     Optional<T> findPermitById(ID id);
  > }
  > 
  > ```
  >
  > 

+ PermitConfig

  > 权限校验和配置
  >
  > ```java
  > public interface PermitConfig {
  > 
  >     /**
  >      * 校验
  >      * @param obj
  >      * @param root
  >      * @return
  >      */
  >     boolean checkPermit(Object obj, PermitRoot root);
  > 
  >      /**
  >      * 获取异常
  >      * @param message
  >      * @return
  >      */
  >     RuntimeException exception(String message);
  > }
  > ```

+ PermitDynamicType

  ```java
  public interface PermitDynamicType {
      /**
       * 动态关联数据查询服务类
       * @return
       */
      Class<? extends Permittable> type();
  }
  ```

  

### 例

> 订单Order和用户User,用户是根资源，而订单不是共有的，而是属于用户私有的。

**用户：**

```java
public class User{
    @Permit(root=true)
    private String id;
    // 省略其他属性和方法
}

@Service
public class UserService implements Permittable<User,String> {
    public Optional<User> findPermitById(String id){
        // 省略具体实现
        return user;
    }
}


```

**订单：**

``` java
public class Order{
    private String id;
    @Permit(clazz=UserSerivce.class)
    private String userId;
}

@Service
public class OrderService implements Permittable<Order,String>{
    @PermitMethod
    public Optional<Order> findPermitById(String id){
        // 省略具体实现
        return order;
    }
}
```

**配置：**

```java
@Component
public class UserPermitConfig implements PermitConfig {
	public boolean checkPermit(Object obj,PermitRoot root){
        // 该例子中User的id属性将被传入,而root是User.id上的注解
        // return true则说明校验通过
        // return false 会继续检查，直至所有的检查都返回false，
        //   则抛出PermissionInsufficientException
        return true;
    }
    public RuntimeException exception(String message){
        return new RuntionException(message);
    }
} 
```

**调用**

```java
public class Handler {
    @Autowired
    private OrderService orderService;
    
    public Order getOrderById(String id){
        return orderService.findPermitById(id).get();
    }
}
```



