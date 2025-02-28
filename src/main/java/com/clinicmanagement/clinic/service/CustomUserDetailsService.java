package com.clinicmanagement.clinic.service;

import com.clinicmanagement.clinic.Entities.UserRole;
import com.clinicmanagement.clinic.Entities.Useraccount;
import com.clinicmanagement.clinic.config.CustomUserDetails;
import com.clinicmanagement.clinic.exception.AppException;
import com.clinicmanagement.clinic.exception.ErrorCode;
import com.clinicmanagement.clinic.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Collection;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

@Service
public class CustomUserDetailsService implements UserDetailsService {

    @Autowired
    private UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Optional<Useraccount> userOpt = userRepository.findByUsername(username);
        if(userOpt.isEmpty()){
            throw  new AppException(ErrorCode.USER_NOT_EXISTED);
        }

        Useraccount user = userOpt.get();
        if(!user.isStatus()){
            throw new AppException(ErrorCode.USER_ACCOUNT_INACTIVE);
        }

        Set<UserRole> roless = user.getUserRoles();
        Collection<GrantedAuthority> grantedAuthoritySet = new HashSet<>();
        for (UserRole userRole : roless) {
            grantedAuthoritySet.add(new SimpleGrantedAuthority(userRole.getRole().getRoleName()));
        }
        return new CustomUserDetails(user,grantedAuthoritySet);
    }
}
