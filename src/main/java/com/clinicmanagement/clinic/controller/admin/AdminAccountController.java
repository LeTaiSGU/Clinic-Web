package com.clinicmanagement.clinic.controller.admin;


import com.clinicmanagement.clinic.Entities.Doctor;
import com.clinicmanagement.clinic.dto.user.UserRequest;
import com.clinicmanagement.clinic.dto.user.UserResponse;
import com.clinicmanagement.clinic.service.DoctorService;
import com.clinicmanagement.clinic.service.UserService;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.validation.ObjectError;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.stream.Collectors;

@Controller
@RequestMapping("/admin")
public class AdminAccountController {

    @Autowired
    private UserService userService;

    @Autowired
    private DoctorService doctorService;

    private List<Doctor> getAvailableDoctors() {
        List<UserResponse> users = userService.findAllUser();
        List<Doctor> doctors = doctorService.getAllDoctors();
        return doctors.stream()
                .filter(doctor -> users.stream().noneMatch(user -> user.getDoctor() != null && user.getDoctor().equals(doctor)))
                .collect(Collectors.toList());
    }

    @GetMapping("/accounts/new")
    public String addAccountForm(Model model) {
        List<Doctor> availableDoctors = getAvailableDoctors();
        model.addAttribute("user", new UserRequest());
        model.addAttribute("doctors", availableDoctors);
        return "/admin/account/addAccount";
    }



    @PostMapping("/accounts/new")
    public String addAccount(@Valid @ModelAttribute("user") UserRequest userRequest,
                             BindingResult bindingResult,
                             Model model,
                             @RequestParam("doctorId") int doctorId) {
        if (bindingResult.hasErrors()) {
            List<Doctor> availableDoctors = getAvailableDoctors();
            model.addAttribute("doctors", availableDoctors);
            return "/admin/account/addAccount";
        }
        try {
            userService.createUserDoctor(userRequest, doctorId);
            return "redirect:/admin/accounts";
        } catch (Exception ex) {
            model.addAttribute("error", "Không thể tạo account!");
            return "/admin/account/addAccount";
        }
    }

    @GetMapping("/accounts")
    public String getAllUserAccounts(
            @RequestParam(defaultValue = "1") int page,
            @RequestParam(defaultValue = "5") int size,
            Model model) {
        Page<UserResponse> userAccountsPage = userService.getAllUsers(PageRequest.of(page - 1, size));

        // Add attributes for the view
        model.addAttribute("userResponse", userAccountsPage.getContent());
        model.addAttribute("currentPage", page);
        model.addAttribute("totalPages", userAccountsPage.getTotalPages());

        return "/admin/account/accounts";
    }


    // Để disable tài khoản
    @PostMapping("/accounts/enable/{id}")
    public String enableAccount(@PathVariable("id") int id) {
        userService.updateAccountStatus(id, true);  // Cập nhật trạng thái thành true
        return "redirect:/admin/accounts";
    }

    // Để disable tài khoản
    @PostMapping("/accounts/disable/{id}")
    public String disableAccount(@PathVariable("id") int id) {
        userService.updateAccountStatus(id, false);
        return "redirect:/admin/accounts";
    }

}
