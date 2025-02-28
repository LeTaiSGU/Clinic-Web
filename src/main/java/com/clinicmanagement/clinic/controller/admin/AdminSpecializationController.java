package com.clinicmanagement.clinic.controller.admin;

import com.clinicmanagement.clinic.Entities.Patient;
import com.clinicmanagement.clinic.Entities.Services;
import com.clinicmanagement.clinic.Entities.Specialization;
import com.clinicmanagement.clinic.dto.SpecializationRequest;
import com.clinicmanagement.clinic.mapper.SpecializationMapper;
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

@Controller
@RequestMapping("/admin/specializations")
public class AdminSpecializationController {

    @Autowired
    private SpecializationService specializationService;

    @Autowired
    private SpecializationMapper specializationMapper;

    @GetMapping
    public String getAllSpecializationPage(@RequestParam(defaultValue = "1") int page,
                                    @RequestParam(defaultValue = "5") int size,
                                    Model model) {
        Page<Specialization> specializationPage = specializationService.getAllSpecializationPage(PageRequest.of(page - 1, size));
        model.addAttribute("specializations", specializationPage.getContent());
        model.addAttribute("currentPage", page);
        model.addAttribute("totalPages", specializationPage.getTotalPages());
        return "admin/specialization/specializations";
    }

    @GetMapping("/create")
    public String showCreateForm(Model model) {
        model.addAttribute("specialization", new SpecializationRequest());
        return "admin/specialization/create";
    }

    @PostMapping("/create")
    public String createSpecialization(@Valid @ModelAttribute("specialization") SpecializationRequest specializationRequest,
                                BindingResult result,
                                Model model) {
        if (result.hasErrors()) {
            return "admin/specialization/create";
        }
        try {
            if(specializationService.findByName(specializationRequest.getName() ) != null){
                result.rejectValue("name", "error.specialization", "Chuyên khoa đã tồn tại");
                return "admin/specialization/create";
            }
            Specialization specialization = specializationMapper.toSpecialization(specializationRequest);
            specialization.setStatus(true);
            specializationService.saveSpecialization(specialization);
            return "redirect:/admin/specializations";
        } catch (Exception e) {
            model.addAttribute("errorMessage", "Không thể tạo chuyên khoa");
            return "admin/specialization/create";
        }
    }

    @GetMapping("/update/{id}")
    public String showUpdateForm(@PathVariable Integer id,Model model) {
        Specialization specialization = specializationService.findById(id);
        model.addAttribute("specialization", specializationMapper.toSpecializationRequest(specialization));
        return "admin/specialization/update";
    }

    @PostMapping("/update")
    public String updateSpecialization(@Valid @ModelAttribute("specialization") SpecializationRequest specializationRequest,
                                BindingResult result,
                                Model model) {

        if (result.hasErrors()) {
            return "admin/specialization/update";
        }

        if (specializationService.findByNameAndNotId(specializationRequest.getName(), specializationRequest.getId()) != null) {
            result.rejectValue("name", "error.specialization", "Chuyên khoa đã tồn tại");
            return "admin/specialization/update"; // Trả về trang form nếu có lỗi
        }
        try {
            specializationService.saveSpecialization(specializationMapper.toSpecialization(specializationRequest));
            return "redirect:/admin/specializations";
        } catch (Exception e) {
            model.addAttribute("errorMessage", "Không thể cập nhật chuyên khoa");
            return "admin/specialization/update";
        }
    }

    @GetMapping("/disable/{id}")
    public String disablePatient(@PathVariable Integer id) {
        Specialization specialization = specializationService.findById(id);
        specialization.setStatus(false);
        specializationService.saveSpecialization(specialization);
        return "redirect:/admin/specializations";
    }

    @GetMapping("/enable/{id}")
    public String enablePatient(@PathVariable Integer id) {
        Specialization specialization = specializationService.findById(id);
        specialization.setStatus(true);
        specializationService.saveSpecialization(specialization);
        return "redirect:/admin/specializations";
    }
}

