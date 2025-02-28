package com.clinicmanagement.clinic.dto.patient;

import jakarta.validation.constraints.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.springframework.format.annotation.DateTimeFormat;

import java.time.LocalDate;

@Data
@NoArgsConstructor
@AllArgsConstructor
@FieldDefaults(level = lombok.AccessLevel.PRIVATE)
public class PatientRequest {

    Integer id;

    @NotBlank(message = "Vui lòng nhập họ tên")
    String fullName;

    @NotNull(message = "Vui lòng chọn ngày sinh")
    @DateTimeFormat(pattern = "yyyy-MM-dd")
    LocalDate dob;

    @NotBlank(message = "Vui lòng nhập địa chỉ")
    String address;

    @NotBlank(message = "Vui lòng nhập số điện thoại")
    @Pattern(regexp = "^[0-9]{10}$", message = "Số điện thoại phải có 10 chữ số")
    String phone;

    @NotBlank(message = "Vui lòng nhập email")
    @Email(message = "Định dạng email không hợp lệ")
    @Size(max = 50, message = "Email phải ít hơn 50 ký tự")
    String email;

    Boolean status;
}
