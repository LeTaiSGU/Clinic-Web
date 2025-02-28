package com.clinicmanagement.clinic.mapper;

import com.clinicmanagement.clinic.Entities.Useraccount;
import com.clinicmanagement.clinic.dto.user.UserResponse;
import com.clinicmanagement.clinic.dto.user.UserRequest;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;

@Mapper(componentModel = "spring")
public interface UserMapper {
    @Mapping(target = "doctor", source = "doctor")
    @Mapping(target = "patient", source = "patient")
    Useraccount toUser(UserRequest userRegisterRes);

    UserResponse toUserReponse(Useraccount user);

//    void updateUser(UserUpdateRequest userUpdateRequest, @MappingTarget Useracount user);
}
