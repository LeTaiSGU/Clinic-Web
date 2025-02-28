package com.clinicmanagement.clinic.dto;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class AppointmentServiceDTO {
    private Integer Id;
    private String note;
    private Integer quantity;
    private Integer appointmentId;
    private Integer serviceId;

}
