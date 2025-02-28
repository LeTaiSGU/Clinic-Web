package com.clinicmanagement.clinic.dto.user;
import com.clinicmanagement.clinic.Entities.Doctor;
import com.clinicmanagement.clinic.Entities.Patient;
import com.clinicmanagement.clinic.Entities.UserRole;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.*;
import lombok.experimental.FieldDefaults;

import java.util.Set;

@Data
@NoArgsConstructor
@AllArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE)
public class UserRequest {
    @NotBlank(message = "* Username is mandatory")
    @Size(min = 4, max = 50, message = "* Username phải ít nhất 4 kí tự")
    String username;

    @NotBlank(message = "Password is mandatory")
    @Size(min = 8, max = 100, message = "Password phải ít nhất 8 kí tự")
    String password;

    String fullname;

    Doctor doctor;

    Patient patient;

    Set<UserRole> role;

    boolean status = true;

}
