package com.clinicmanagement.clinic.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.FieldDefaults;

@Data
@NoArgsConstructor
@AllArgsConstructor
@FieldDefaults(level = lombok.AccessLevel.PRIVATE)
public class SpecializationRequest {

    private Integer id;

    @NotBlank(message = "Vui lòng nhập tên chuyên khoa")
    private String name;
    private Boolean status;
}
