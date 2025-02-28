package com.clinicmanagement.clinic.controller.admin;

import com.clinicmanagement.clinic.Entities.Doctor;
import com.clinicmanagement.clinic.Entities.Specialization;
import com.clinicmanagement.clinic.dto.doctor.DoctorRequest;
import com.clinicmanagement.clinic.dto.doctor.doctorReponse;
import com.clinicmanagement.clinic.dto.user.UserResponse;
import com.clinicmanagement.clinic.mapper.DoctorMapper;
import com.clinicmanagement.clinic.service.DoctorService;
import com.clinicmanagement.clinic.service.SpecializationService;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Optional;

@Controller
@RequestMapping("/admin/doctors")
public class AdminDoctorController {

    @Autowired
    private DoctorService doctorService;
    @Autowired
    private SpecializationService specializationService;
    @Autowired
    private DoctorMapper doctorMapper;

    @GetMapping
    public String getAllDoctors(@RequestParam(defaultValue = "1") int page,
                                @RequestParam(defaultValue = "5") int size,
                                Model model) {
        Page<Doctor> doctorPage = doctorService.getAllUsers(PageRequest.of(page - 1, size));
        model.addAttribute("doctors", doctorPage.getContent());
        model.addAttribute("currentPage", page);
        model.addAttribute("totalPages", doctorPage.getTotalPages());
        return "admin/doctor/doctors";
    }

    @GetMapping("/create")
    public String showCreateForm(Model model) {
        model.addAttribute("doctor", new DoctorRequest());
        model.addAttribute("specializations", specializationService.getAllSpecializations());
        return "admin/doctor/create";
    }

    @PostMapping("/create")
    public String createDoctor(@Valid @ModelAttribute("doctor") DoctorRequest doctorRequest,
                               BindingResult result,
                               Model model) {
        List<Specialization> specializations = specializationService.getAllSpecializations();
        if (result.hasErrors()) {
            model.addAttribute("specializations", specializations);
            return "admin/doctor/create";
        }
        try {
            if(doctorService.findByEmail(doctorRequest.getEmail()) != null){
                result.rejectValue("email", "error.doctor", "Email đã tồn tại");
                model.addAttribute("specializations", specializations);
                return "admin/doctor/create";
            }
            Doctor doctor = doctorMapper.toDoctor(doctorRequest);
            doctor.setStatus(true);
            doctorService.saveDoctor(doctor);
            return "redirect:/admin/doctors";
        } catch (Exception e) {
            model.addAttribute("errorMessage", "Không thể tạo bác sĩ");
            return "admin/doctor/create";
        }
    }

    @GetMapping("/update/{id}")
    public String showUpdateForm(@PathVariable Integer id,Model model) {
        Optional<Doctor> doctor = doctorService.findById(id);
        model.addAttribute("doctor", doctorMapper.toDoctorRequest(doctor.get()));
        model.addAttribute("specializations", specializationService.getAllSpecializations());
        return "admin/doctor/update";
    }

    @PostMapping("/update")
    public String updateDoctor(@Valid @ModelAttribute("doctor") DoctorRequest doctorRequest,
                               BindingResult result,
                               Model model) {

        List<Specialization> specializations = specializationService.getAllSpecializations();

        if (result.hasErrors()) {
            model.addAttribute("specializations", specializations);
            return "admin/doctor/update";
        }

        if (doctorService.findByEmailAndNotId(doctorRequest.getEmail(), doctorRequest.getId()).isPresent()) {
            model.addAttribute("specializations", specializations);
            result.rejectValue("email", "error.doctor", "Email đã tồn tại");
            return "admin/doctor/update"; // Trả về trang form nếu có lỗi
        }
        try {
            doctorService.saveDoctor(doctorMapper.toDoctor(doctorRequest));
            return "redirect:/admin/doctors";
        } catch (Exception e) {
            model.addAttribute("errorMessage", "Không thể cập nhật bác sĩ");
            model.addAttribute("specializations", specializations);
            return "admin/doctor/update";
        }
    }

    @GetMapping("/disable/{id}")
    public String disableDoctor(@PathVariable Integer id) {
        Optional<Doctor> doctor = doctorService.findById(id);
        doctor.get().setStatus(false);
        doctorService.saveDoctor(doctor.get());
        return "redirect:/admin/doctors";
    }

    @GetMapping("/enable/{id}")
    public String enableDoctor(@PathVariable Integer id) {
        Optional<Doctor> doctor = doctorService.findById(id);
        doctor.get().setStatus(true);
        doctorService.saveDoctor(doctor.get());
        return "redirect:/admin/doctors";
    }
}

