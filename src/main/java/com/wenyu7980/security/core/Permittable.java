package com.wenyu7980.security.core;
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

import java.util.Optional;

/**
 * 权限控制接口
 * @author:wenyu
 * @date:2019/12/18
 */
public interface Permittable<T, ID> {
    /**
     * 类型
     * @return
     */
    default Class<? extends Permittable> type() {
        return this.getClass();
    }

    /**
     * 通过id获取数据
     * @param id
     * @return
     */
    Optional<T> findPermitById(ID id);
}
