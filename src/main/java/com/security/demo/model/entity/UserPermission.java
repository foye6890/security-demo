package com.security.demo.model.entity;

import java.time.LocalDateTime;
import lombok.Data;

@Data
public class UserPermission {

    private Long id;
    private Long userId;
    private String resource;
    private String action;
    private String permission;
    private LocalDateTime grantedAt;
}