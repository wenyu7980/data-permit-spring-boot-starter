package com.wenyu.security.annotation;
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

import com.wenyu.security.core.Permittable;

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
public @interface PermitSuperior {
    /** 属性名 */
    String[] names() default {};

    /** 数据获取校验类 */
    Class<? extends Permittable> clazz() default Permittable.class;
}
