package com.wenyu7980.security.annotation;
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

import com.wenyu7980.security.core.Permittable;

import java.lang.annotation.*;

/**
 * 权限上级资源
 * @author:wenyu
 * @date:2019/12/18
 */
@Target(ElementType.FIELD)
@Retention(RetentionPolicy.RUNTIME)
@Documented
@Inherited
public @interface Permit {
    /**
     * 类上注解时，复合key时使用
     * @return
     */
    String[] names() default {};

    /**
     * 关联数据查询服务类
     * 如果该属性和dynamic都没有设定，则认为校验属性是复合属性
     * @return
     */
    Class<? extends Permittable> clazz() default Permittable.class;

    /**
     * 动态关联数据查询服务类
     * 由属性决定关联服务类
     * 该属性的类型必须是{@link com.wenyu7980.security.core.PermitDynamicType} 的子类
     * @return
     */
    String dynamic() default "";

    /**
     * 判断是否是根校验
     * 如果是根校验会调用{@link com.wenyu7980.security.core.PermitConfig#checkPermit(Object, Permit)}
     * 如果否，递归校验属性
     * @return
     */
    boolean root() default false;

    /**
     * 根校验的辅助属性
     * @return
     */
    String type() default "";
}
