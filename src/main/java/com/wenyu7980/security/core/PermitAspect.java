package com.wenyu7980.security.core;

import com.wenyu7980.security.annotation.PermitMethod;
import com.wenyu7980.security.annotation.PermitRoot;
import com.wenyu7980.security.annotation.PermitSuperior;
import com.wenyu7980.security.annotation.PermitSuperiors;
import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.annotation.AfterReturning;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Pointcut;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.stereotype.Component;

import java.lang.reflect.*;
import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
/**
 * Copyright wenyu
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * 资源权限控制核心AOP
 * @author:wenyu
 * @date:2019/12/18
 */
@Component
@Aspect
public class PermitAspect implements ApplicationContextAware {
    /** 保存数据访问bean */
    private List<Permittable> permittables;

    @Autowired
    private PermitConfig permitUserCheck;

    @Pointcut("@annotation(com.wenyu.security.annotation.PermitMethod)")
    public void method() {
    }

    /**
     * 对PermitMethod切面，判断是否对返回数据有访问权限
     * 如果没有权限，抛出PermissionInsufficientException异常
     *
     * @param ret
     * @throws IllegalAccessException
     * @throws NoSuchMethodException
     * @throws NoSuchFieldException
     * @throws InstantiationException
     * @throws InvocationTargetException
     */
    @AfterReturning(pointcut = "method() && @annotation(permitMethod)", returning = "ret")
    public void permit(JoinPoint joinPoint, Object ret,
            PermitMethod permitMethod)
            throws IllegalAccessException, NoSuchMethodException,
            NoSuchFieldException, InstantiationException,
            InvocationTargetException {

        if (Objects.isNull(ret)) {
            return;
        }
        if (ret instanceof Optional && !((Optional) ret).isPresent()) {
            return;
        }
        if (!this.checkPermit(ret)) {
            throw new PermissionInsufficientException(MessageFormat
                    .format(permitMethod.message(), joinPoint.getArgs()[0],
                            joinPoint.getSignature().getDeclaringType()
                                    .getSimpleName()));
        }
    }

    /**
     * 获取类中roots同时校验Superior
     * @param obj
     * @return
     * @throws IllegalAccessException
     * @throws NoSuchMethodException
     * @throws InstantiationException
     * @throws InvocationTargetException
     * @throws NoSuchFieldException
     * @return true: 允许访问
     *         false: 不允许访问
     */
    private boolean checkPermit(Object obj)
            throws IllegalAccessException, NoSuchMethodException,
            InstantiationException, InvocationTargetException,
            NoSuchFieldException {
        if (Objects.isNull(obj)) {
            return false;
        }
        // Optional 处理
        if (obj instanceof Optional) {
            if (!((Optional) obj).isPresent()) {
                return false;
            }
            obj = ((Optional) obj).get();
        }
        // 数据类型
        Class<?> clazz = obj.getClass();

        // 遍历属性
        Field[] fields = clazz.getDeclaredFields();
        for (int i = 0; i < fields.length; i++) {
            Field field = fields[i];
            // 根
            PermitRoot root = field.getAnnotation(PermitRoot.class);
            if (Objects.nonNull(root)) {
                field.setAccessible(true);
                if (Objects.nonNull(field.get(obj))) {
                    if (this.permitUserCheck
                            .checkPermit(field.get(obj), root)) {
                        return true;
                    }
                }
            }
        }
        // 属性上的supperior处理
        for (int i = 0; i < fields.length; i++) {
            Field field = fields[i];
            // 上级资源
            PermitSuperior superior = field.getAnnotation(PermitSuperior.class);
            if (Objects.nonNull(superior)) {
                field.setAccessible(true);
                Object value = field.get(obj);
                if (Objects.isNull(value)) {
                    continue;
                }
                if (value.getClass().isPrimitive() || value instanceof String) {
                    // 基本数据类型或者String类型
                    if (this.checkSuperior(superior.getClass(),
                            field.get(obj))) {
                        return true;
                    }
                } else {
                    // 复杂数据类型
                    if (this.checkPermit(field.get(obj))) {
                        return true;
                    }
                }
            }
        }
        // 类注解校验
        PermitSuperiors superiors = obj.getClass()
                .getAnnotation(PermitSuperiors.class);
        if (Objects.nonNull(superiors)) {
            out:
            for (int i = 0; i < superiors.superiors().length; i++) {
                PermitSuperior superior = superiors.superiors()[i];
                // 获取参数
                assert superior.names().length > 0 : MessageFormat
                        .format("{0}的PermitSuperior的names属性不能为空",
                                clazz.getName());
                Object[] parameters = new Object[superior.names().length];
                for (int j = 0; j < superior.names().length; j++) {
                    Field field = clazz.getDeclaredField(superior.names()[j]);
                    field.setAccessible(true);
                    if (Objects.isNull(field.get(obj))) {
                        continue out;
                    }
                    parameters[j] = field.get(obj);
                }
                // 校验
                if (this.checkSuperior(superior.clazz(), parameters)) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * 校验复杂上级资源
     * @param clazz
     * @param parameters
     * @throws NoSuchMethodException
     * @throws IllegalAccessException
     * @throws InvocationTargetException
     * @throws InstantiationException
     */
    private boolean checkSuperior(Class<?> clazz, Object... parameters)
            throws NoSuchMethodException, IllegalAccessException,
            InvocationTargetException, InstantiationException,
            NoSuchFieldException {
        Permittable permittable = this.permittables.stream()
                .filter(permit -> clazz.isAssignableFrom(permit.type()))
                .findFirst().orElseThrow(() -> new RuntimeException(
                        MessageFormat.format("{0}没有Permittable相应的实现",
                                clazz.getName())));
        Method method = permittable.getClass()
                .getMethod("findPermitById", Object.class);
        Type[] types = permittable.type().getGenericInterfaces();
        Class<?> actual = null;
        for (int j = 0; j < types.length; j++) {
            if (Objects.equals(((ParameterizedType) types[j]).getRawType(),
                    Permittable.class)) {
                // 第二个泛型类型参数为查询ID类型
                actual = (Class<?>) ((ParameterizedType) types[j])
                        .getActualTypeArguments()[1];
                break;
            }
        }
        // 获取构造函数
        Constructor[] constructors = actual.getConstructors();
        for (int j = 0; j < constructors.length; j++) {
            if (constructors[j].getParameterCount() == parameters.length) {
                Optional optional = permittable.findPermitById(
                        constructors[j].newInstance(parameters));
                return this.checkPermit(optional);
            }
        }
        throw new RuntimeException(MessageFormat
                .format("{0}构造函数的参数与PermitSuperiors注解中的{1}的names长度不一致",
                        actual.getName(), clazz.getName()));
    }

    @Override
    public void setApplicationContext(ApplicationContext applicationContext)
            throws BeansException {
        this.permittables = new ArrayList<>();
        this.permittables
                .addAll(applicationContext.getBeansOfType(Permittable.class)
                        .values());
    }
}
