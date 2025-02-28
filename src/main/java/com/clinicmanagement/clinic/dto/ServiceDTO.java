package com.clinicmanagement.clinic.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.boot.context.properties.bind.DefaultValue;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class ServiceDTO {
    @NotBlank(message = "Service is required")
    private String serviceName;
    private String description;
    @NotNull(message = "Price is required")
    private double price;
    private boolean status = true;
}
