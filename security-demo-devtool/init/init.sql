CREATE TABLE user_permission (
    id          BIGINT AUTO_INCREMENT PRIMARY KEY,

    user_id     BIGINT      NOT NULL COMMENT '用户ID',
    resource    VARCHAR(50) NOT NULL COMMENT '资源标识，如 ARTICLE / USER / ORDER',
    action      VARCHAR(20) NOT NULL COMMENT '操作类型：CREATE / READ / UPDATE / DELETE',

    permission  VARCHAR(100) NOT NULL COMMENT 'Spring Security 权限字符串',
    granted_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    UNIQUE KEY uk_user_perm (user_id, resource, action),
    INDEX idx_user_id (user_id)
) COMMENT='用户CRUD权限表（Spring Security授权源）';
