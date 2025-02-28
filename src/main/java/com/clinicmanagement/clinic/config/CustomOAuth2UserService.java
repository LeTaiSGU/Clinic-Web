package com.clinicmanagement.clinic.config;

import com.clinicmanagement.clinic.Entities.Patient;
import com.clinicmanagement.clinic.Entities.Role;
import com.clinicmanagement.clinic.Entities.UserRole;
import com.clinicmanagement.clinic.Entities.Useraccount;
import com.clinicmanagement.clinic.dto.user.UserRequest;
import com.clinicmanagement.clinic.enums.Roles;
import com.clinicmanagement.clinic.exception.AppException;
import com.clinicmanagement.clinic.exception.ErrorCode;
import com.clinicmanagement.clinic.mapper.UserMapper;
import com.clinicmanagement.clinic.repository.RoleRepository;
import com.clinicmanagement.clinic.repository.UserRepository;
import com.clinicmanagement.clinic.repository.UserRoleRepository;
import com.clinicmanagement.clinic.service.PatientService;
import com.clinicmanagement.clinic.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Component;

import java.time.LocalDate;
import java.util.*;

@Component
public class CustomOAuth2UserService implements OAuth2UserService<OAuth2UserRequest, OAuth2User> {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private UserRoleRepository userRoleRepository;

    @Autowired
    private RoleRepository roleRepository;

    @Autowired
    private UserMapper userMapper;

    @Autowired
    private PatientService patientService;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) {
        OAuth2User oAuth2User = new DefaultOAuth2UserService().loadUser(userRequest);

        Map<String, Object> attributes = oAuth2User.getAttributes();
        String email = (String) attributes.get("email");
        String name = (String) attributes.get("name");

        if (!patientService.checkByEmail(email)) {
            LocalDate dateDefault = LocalDate.of(1999, 1, 1);
            Patient patient = Patient.builder()
                    .fullName(name)
                    .email(email)
                    .phone(null)
                    .address("")
                    .dob(dateDefault)
                    .status(true)
                    .build();
            patientService.savePatient(patient);
            UserRequest userReq = new UserRequest();
            userReq.setUsername(email);
            userReq.setPatient(patient);
            userReq.setPassword(UUID.randomUUID().toString());
            Useraccount user = userMapper.toUser(userReq);
            userRepository.save(user);
            Role role = roleRepository.findByRoleName(Roles.USER.name());
            UserRole userRole = userRoleRepository.save(UserRole.builder()
                    .user(user)
                    .role(role)
                    .build());
            userRepository.save(user);
        }

        Useraccount user = userRepository.findByUsername(email)
                .orElseThrow(() -> new AppException(ErrorCode.USER_NOT_EXISTED));

        Set<UserRole> roless = user.getUserRoles();
        Collection<GrantedAuthority> grantedAuthoritySet = new HashSet<>();
        for (UserRole userRole : roless) {
            grantedAuthoritySet.add(new SimpleGrantedAuthority(userRole.getRole().getRoleName()));
        }

        return new DefaultOAuth2User(grantedAuthoritySet, attributes, "email");
    }
}
