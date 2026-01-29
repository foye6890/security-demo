package com.security.demo.auth.mapper;

import com.security.demo.model.entity.UserPermission;
import java.util.List;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

@Mapper
public interface UserPermissionMapper {
    /**
     * Spring Security 授权核心方法
     * 根据 userId 查询所有权限字符串
     */
    List<String> selectPermissionsByUserId(@Param("userId") Long userId);

    /**
     * 查询完整权限对象（管理画面 / 审计用）
     */
    List<UserPermission> selectByUserId(@Param("userId") Long userId);

    /**
     * 新增权限
     */
    int insert(UserPermission permission);

    /**
     * 删除用户的某个权限
     */
    int delete(
        @Param("userId") Long userId,
        @Param("resource") String resource,
        @Param("action") String action
    );
}
