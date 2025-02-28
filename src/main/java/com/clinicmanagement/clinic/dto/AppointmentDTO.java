package com.clinicmanagement.clinic.dto;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;
import lombok.Setter;

import java.time.LocalDate;
import java.time.LocalTime;
import java.util.List;

@Getter
@Setter

public class AppointmentDTO {
    private int id;
    private LocalDate appointmentDate;
    private LocalTime appointmentTime;
    private String status;
    private Integer patientId;
    private Integer doctorId;
    private List<ServiceDTO> services;
}
