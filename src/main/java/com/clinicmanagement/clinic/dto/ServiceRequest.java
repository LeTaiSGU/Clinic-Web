package com.clinicmanagement.clinic.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ServiceRequest {

    private Integer id;

    @NotBlank(message = "Vui lòng nhập tên dịch vụ")
    private String serviceName;

    @NotBlank(message = "Vui lòng nhập mô tả")
    private String description;

    @NotNull(message = "Vui lòng nhập giá")
    private double price;

    private Boolean status;
}
