package com.clinicmanagement.clinic.mapper;

import com.clinicmanagement.clinic.Entities.Specialization;
import com.clinicmanagement.clinic.dto.SpecializationRequest;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;

@Mapper(componentModel = "spring")
public interface SpecializationMapper {
    @Mapping(target = "id", source = "id")
    Specialization toSpecialization(SpecializationRequest specializationRequest);

    @Mapping(target = "id", source = "id")
    SpecializationRequest toSpecializationRequest(Specialization specialization);
}
