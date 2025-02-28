package com.clinicmanagement.clinic.controller;

import com.clinicmanagement.clinic.Entities.Patient;
import com.clinicmanagement.clinic.Entities.Useraccount;
import com.clinicmanagement.clinic.dto.user.UserRequest;
import com.clinicmanagement.clinic.mapper.UserMapper;
import com.clinicmanagement.clinic.service.DoctorService;
import com.clinicmanagement.clinic.service.EmailService;
import com.clinicmanagement.clinic.service.PatientService;
import com.clinicmanagement.clinic.service.UserService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.time.LocalDate;
import java.util.Optional;
import java.util.concurrent.ThreadLocalRandom;

@Controller
public class UserController {
    @Autowired
    private UserService userService;

    @Autowired
    private PatientService patientService;

    @Autowired
    private DoctorService doctorService;

    @Autowired
    private EmailService emailService;

    @Autowired
    private UserMapper userMapper;


    @PostMapping("/register")
    public String register(@ModelAttribute("user") @Valid UserRequest userRequest) {
        try {
            LocalDate dateDefault = LocalDate.of(1999, 1, 1);
            Patient patient = Patient.builder()
                    .fullName(userRequest.getFullname())
                    .email(null)
                    .phone(null)
                    .address("")
                    .dob(dateDefault)
                    .status(true)
                    .build();
            patientService.savePatient(patient);
            userRequest.setPatient(patient);
            userService.createUser(userRequest);
        } catch (Exception e) {
            e.printStackTrace();
            return "login/register";
        }
        return "redirect:/login";
    }

//    @GetMapping("/myInfo")
//    public String myinfo(){
//        return "/test/getuser";
//    }

    @GetMapping("/forgotpassword")
    public String forgotpass(){
        return "/login/forgot_password";
    }

    @PostMapping("/forgotpassword")
    public String processForgotPass(HttpServletRequest request, Model model){
        String email = request.getParameter("email");
        String token = String.valueOf(ThreadLocalRandom.current().nextInt(100000, 1000000));
        Useraccount user = userService.getByEmail(email);
        if (user == null) {
            model.addAttribute("error", "Không tìm thấy tài khoản với email này.");
            return "/login/forgot_password";
        }
        userService.updateResetPasswordToken(user,token);
        String subject = "Đây là email khôi phục mật khẩu";
        String text = "Mã xác thực của bạn là: " + token;
        emailService.sendSimpleEmail(email, subject, text);
        model.addAttribute("email", email);
        model.addAttribute("token",token);
        return "/login/verifyToken";
    }

    @GetMapping("/resetPass")
    public String resetPassForm(@RequestParam(value = "token") String token, Model model) {
        System.out.println("Received token: " + token);
        model.addAttribute("token",token);
        return "/login/reset_pass";
    }

    @PostMapping("/verifytoken")
    public String showResetPasswordForm(@Param(value = "token") String token, Model model) {
        Optional<Useraccount> user = userService.getByResetPasswordToken(token);
        if (user.isPresent()) {
            System.out.println(user.get().getUsername());
            return "redirect:/resetPass?token=" + token;
        }
        model.addAttribute("error", "Mã xác thực không đúng!");
        return "/login/verifyToken";
    }

    @PostMapping("/resetPass")
    public String processResetPassword(
            @RequestParam("token") String token,
            HttpServletRequest request,
            Model model,
            RedirectAttributes redirectAttributes) {
        String newPass = request.getParameter("newPass");
        System.out.println("Token: "+ token);
        Optional<Useraccount> user = userService.getByResetPasswordToken(token);

        if (user.isEmpty()) {
            model.addAttribute("error", "Mã xác thực không hợp lệ.");
            return "/login/reset_pass";
        }

        try {
            userService.updatePassword(user.get(), newPass);
            redirectAttributes.addFlashAttribute("success", "Đổi mật khẩu thành công");
            return "redirect:/login";
        } catch (Exception e) {
            model.addAttribute("error", "Có lỗi xảy ra khi cập nhật mật khẩu");
            return "/login/reset_pass";
        }
    }


}
