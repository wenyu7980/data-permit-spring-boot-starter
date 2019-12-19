package com.wenyu.security.core;
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

import com.wenyu.security.annotation.PermitRoot;
import org.springframework.lang.NonNull;

/**
 * 数据权限校验接口，用户需要实现
 * 以Bean的形式注入到框架中
 * 以Bean的形式注入到框架中
 * @author:wenyu
 * @date:2019/12/18
 */
public interface PermitConfig {

    /**
     * 校验
     * @param obj
     * @param root
     * @return
     */
    boolean checkPermit(Object obj, PermitRoot root);

    /**
     * 是否是基础数据类型
     * @param obj
     * @return
     */
    default boolean isPrimitive(@NonNull Object obj) {
        return obj.getClass().isPrimitive() || obj instanceof String;
    }
}
