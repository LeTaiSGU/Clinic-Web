package com.clinicmanagement.clinic.mapper;

import com.clinicmanagement.clinic.Entities.Doctor;
import com.clinicmanagement.clinic.Entities.Specialization;
import com.clinicmanagement.clinic.dto.doctor.DoctorRequest;
import com.clinicmanagement.clinic.dto.doctor.doctorReponse;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;

@Mapper(componentModel = "spring")
public interface DoctorMapper {

    @Mapping(target = "id", source = "id")
    @Mapping(target = "specialization", expression = "java(mapSpecialization(doctorRequest.getSpecialization_id()))")
    Doctor toDoctor(DoctorRequest doctorRequest);


    @Mapping(target = "id", source = "id")
    @Mapping(target = "specialization_id", source = "specialization.id")
    DoctorRequest toDoctorRequest(Doctor doctor);

    doctorReponse toDoctorReponse(Doctor doctor);

    default Specialization mapSpecialization(Integer specializationId) {
        if (specializationId == null) {
            return null;
        }
        Specialization specialization = new Specialization();
        specialization.setId(specializationId);
        return specialization;
    }


}
