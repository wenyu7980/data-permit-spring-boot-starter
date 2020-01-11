package com.wenyu7980.security.core;

/**
 * 动态关联数据查询服务类
 * @author:wenyu
 * @date:2020/1/10
 */
public interface PermitDynamicType {
    /**
     * 动态关联数据查询服务类
     * @return
     */
    Class<? extends Permittable> type();
}
