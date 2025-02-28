package com.clinicmanagement.clinic.mapper;

import com.clinicmanagement.clinic.Entities.Services;
import com.clinicmanagement.clinic.Entities.Specialization;
import com.clinicmanagement.clinic.dto.ServiceDTO;
import com.clinicmanagement.clinic.dto.ServiceRequest;
import com.clinicmanagement.clinic.dto.SpecializationRequest;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;
import org.mapstruct.MappingTarget;

@Mapper(componentModel = "spring")
public interface ServiceMapper {
    @Mapping(target = "id", source = "id")
    Services toServices(ServiceRequest serviceRequest);

    @Mapping(target = "id", source = "id")
    ServiceRequest toServiceRequest(Services services);
}
