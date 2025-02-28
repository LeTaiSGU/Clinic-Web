package com.clinicmanagement.clinic.mapper;

import com.clinicmanagement.clinic.Entities.Patient;
import com.clinicmanagement.clinic.dto.patient.PatientRequest;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;

@Mapper(componentModel = "spring")
public interface PatientMapper {

    @Mapping(target = "id", source = "id")
    Patient toPatient(PatientRequest patientRequest);

    @Mapping(target = "id", source = "id")
    PatientRequest toPatientRequest(Patient patient);

}
