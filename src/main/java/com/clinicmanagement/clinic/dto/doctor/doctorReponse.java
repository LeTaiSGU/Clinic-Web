package com.clinicmanagement.clinic.dto.doctor;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class doctorReponse {
    private Integer id;
    private String fullName;
    private Boolean gender;
    private String phone;
    private String email;
    private Integer specialization_id;
    private Boolean status;
}
