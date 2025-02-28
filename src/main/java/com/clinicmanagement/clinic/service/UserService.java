package com.clinicmanagement.clinic.service;

import com.clinicmanagement.clinic.Entities.Doctor;
import com.clinicmanagement.clinic.Entities.Role;
import com.clinicmanagement.clinic.Entities.UserRole;
import com.clinicmanagement.clinic.Entities.Useraccount;
import com.clinicmanagement.clinic.dto.ChangePasswordDTO;
import com.clinicmanagement.clinic.dto.user.UserRequest;
import com.clinicmanagement.clinic.dto.user.UserResponse;
import com.clinicmanagement.clinic.enums.Roles;
import com.clinicmanagement.clinic.exception.AppException;
import com.clinicmanagement.clinic.exception.ErrorCode;
import com.clinicmanagement.clinic.mapper.UserMapper;
import com.clinicmanagement.clinic.repository.DoctorRepository;
import com.clinicmanagement.clinic.repository.RoleRepository;
import com.clinicmanagement.clinic.repository.UserRepository;
import com.clinicmanagement.clinic.repository.UserRoleRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;


import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;


@Service
public class UserService{
    private static final Logger log = LoggerFactory.getLogger(UserService.class);
    @Autowired
    private UserRepository userRepo;

    @Autowired
    private DoctorRepository doctorRepository;

    @Autowired
    private UserRoleRepository userRoleRepository;

    @Autowired
    private RoleRepository roleRepository;

    @Autowired
    private UserMapper userMapper;

    @Autowired
    private PasswordEncoder passwordEncoder;

    public List<UserResponse> findAllUser() {
        List<Useraccount> users = userRepo.findAll();
        return users.stream()
                .map(userMapper::toUserReponse)
                .collect(Collectors.toList());
    }

    public Page<UserResponse> getAllUsers(Pageable pageable) {
        return userRepo.findAll(pageable).map(userMapper::toUserReponse);
    }

    public UserResponse getByID(int id){
        return userMapper.toUserReponse(userRepo.findById(id)
                .orElseThrow(() -> new RuntimeException("User not found")));
    }

    public void  createUserDoctor(UserRequest userRequest,int idDoctor){
        Doctor doctor = doctorRepository.findById(idDoctor)
                .orElseThrow(() -> new IllegalArgumentException("Doctor with ID " + idDoctor + " not found"));
        Useraccount user = userMapper.toUser(userRequest);
        user.setPassword(passwordEncoder.encode(userRequest.getPassword()));
        user.setDoctor(doctor);
        try {
            user = userRepo.save(user);
            Role role = roleRepository.findByRoleName(Roles.DOCTOR.name());
            UserRole userRole = userRoleRepository.save(UserRole.builder()
                    .user(user)
                    .role(role)
                    .build());
            userRepo.save(user);
        } catch (Exception ex) {
            throw ex;
        }
    }

    public void createUser(UserRequest userRequest) {
        if (userRepo.existsByUsername(userRequest.getUsername()))
            throw new AppException(ErrorCode.USER_EXISTED);
        Useraccount user = userMapper.toUser(userRequest);
        user.setPassword(passwordEncoder.encode(userRequest.getPassword()));
        try {
            user = userRepo.save(user);
            Role role = roleRepository.findByRoleName(Roles.USER.name());
            UserRole userRole = userRoleRepository.save(UserRole.builder()
                    .user(user)
                    .role(role)
                    .build());
            userRepo.save(user);
        } catch (Exception ex) {
            throw ex;
        }
    }


    public Useraccount getByEmail(String email) {
        try{
            return userRepo.findByPatient_Email(email);
        } catch (Exception ex){
            throw new IllegalArgumentException("Could not find any customer with the email " + email);
        }
    }


    public Useraccount getByName(String username) {
        Optional<Useraccount> optionalUser = userRepo.findByUsername(username);
        return optionalUser.orElseThrow(() -> new AppException(ErrorCode.USER_NOT_EXISTED));
    }


    public void updateResetPasswordToken(Useraccount useraccount, String token) {
        useraccount.setResetPasswordToken(token);
        userRepo.save(useraccount);
    }

    public void updatePassword(Useraccount customer, String newPassword) {
        BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
        String encodedPassword = passwordEncoder.encode(newPassword);
        customer.setPassword(encodedPassword);

        customer.setResetPasswordToken(null);
        userRepo.save(customer);
    }

    public Optional<Useraccount> getByResetPasswordToken(String token) {
        return userRepo.findByResetPasswordToken(token);
    }

    public void updateAccountStatus(int userId, boolean status) {
        Optional<Useraccount> userOpt = userRepo.findById(userId);
        if (userOpt.isPresent()) {
            Useraccount user = userOpt.get();
            user.setStatus(status);  // Cập nhật trạng thái tài khoản
            userRepo.save(user);  // Lưu thay đổi vào cơ sở dữ liệu
        }
    }

    //================================TOANLD===============================
    public void changePassword(ChangePasswordDTO changePasswordDTO) {
        var context = SecurityContextHolder.getContext();
        String username = context.getAuthentication().getName();

        Useraccount user = userRepo.findByUsername(username)
                .orElseThrow(() -> new AppException(ErrorCode.USER_NOT_EXISTED));

        System.out.println("Current Password from DTO: " + changePasswordDTO.getCurrentPassword());
        System.out.println("Current Password: " + user.getPassword());

        //Kiểm tra mật khẩu hiện tại
        if (!passwordEncoder.matches(changePasswordDTO.getCurrentPassword(), user.getPassword())) {
            throw new AppException(ErrorCode.INVALID_PASSWORD);
        }

        // Kiểm tra mật khẩu mới và xác nhận mật khẩu
        if (!changePasswordDTO.getNewPassword().equals(changePasswordDTO.getConfirmNewPassword())) {
            System.out.println("New Password: " + changePasswordDTO.getNewPassword());
        }

        // Kiểm tra độ dài mật khẩu
        if (changePasswordDTO.getNewPassword().length() < 8) {
            System.out.println("Mat khau co do dai nho hon 8 ky tu");
        }


        String encodedPassword = passwordEncoder.encode(changePasswordDTO.getNewPassword());

        user.setPassword(encodedPassword);
        userRepo.save(user);

    }

}
