package com.app.controller.dto;

import java.util.List;

import org.springframework.validation.annotation.Validated;

import jakarta.validation.constraints.Size;

@Validated
public record AuthCreateRoleRequest(
        @Size(max = 3, message = "The user cannot have more than 3 roles") List<String> roleListName) {

}
