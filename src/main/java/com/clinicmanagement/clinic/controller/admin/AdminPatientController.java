package com.clinicmanagement.clinic.controller.admin;

import com.clinicmanagement.clinic.Entities.Doctor;
import com.clinicmanagement.clinic.Entities.Patient;
import com.clinicmanagement.clinic.dto.patient.PatientRequest;
import com.clinicmanagement.clinic.mapper.PatientMapper;
import com.clinicmanagement.clinic.service.PatientService;
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
@RequestMapping("/admin/patients")
public class AdminPatientController {

    @Autowired
    private PatientService patientService;
    @Autowired
    private PatientMapper patientMapper;

    @GetMapping
    public String getAllPatients(@RequestParam(defaultValue = "1") int page,
                                @RequestParam(defaultValue = "5") int size,
                                Model model) {
        Page<Patient> patientPage = patientService.getAllPatientPage(PageRequest.of(page - 1, size));
        model.addAttribute("patients", patientPage.getContent());
        model.addAttribute("currentPage", page);
        model.addAttribute("totalPages", patientPage.getTotalPages());
        return "admin/patient/patients";
    }

    @GetMapping("/create")
    public String showCreateForm(Model model) {
        model.addAttribute("patient", new PatientRequest());
        return "admin/patient/create";
    }

    @PostMapping("/create")
    public String createPatient(@Valid @ModelAttribute("patient") PatientRequest patientRequest,
                               BindingResult result,
                               Model model) {
        if (result.hasErrors()) {
            return "admin/patient/create";
        }
        try {
            if(patientService.findByEmail(patientRequest.getEmail()) != null){
                result.rejectValue("email", "error.patient", "Email đã tồn tại");
                return "admin/patient/create";
            }
            Patient patient = patientMapper.toPatient(patientRequest);
            patient.setStatus(true);
            patientService.savePatient(patient);
            return "redirect:/admin/patients";
        } catch (Exception e) {
            model.addAttribute("errorMessage", "Không thể tạo bác sĩ");
            return "admin/patient/create";
        }
    }

    @GetMapping("/update/{id}")
    public String showUpdateForm(@PathVariable Integer id,Model model) {
        Patient patient = patientService.findById(id);
        model.addAttribute("patient", patientMapper.toPatientRequest(patient));
        return "admin/patient/update";
    }

    @PostMapping("/update")
    public String updatePatient(@Valid @ModelAttribute("patient") PatientRequest patientRequest,
                               BindingResult result,
                               Model model) {

        if (result.hasErrors()) {
            return "admin/patient/update";
        }

        if (patientService.findByEmailAndNotId(patientRequest.getEmail(), patientRequest.getId()).isPresent()) {
            result.rejectValue("email", "error.patient", "Email đã tồn tại");
            return "admin/patient/update"; // Trả về trang form nếu có lỗi
        }
        try {
            patientService.savePatient(patientMapper.toPatient(patientRequest));
            return "redirect:/admin/patients";
        } catch (Exception e) {
            model.addAttribute("errorMessage", "Không thể cập nhật bác sĩ");
            return "admin/patient/update";
        }
    }

    @GetMapping("/disable/{id}")
    public String disablePatient(@PathVariable Integer id) {
        Patient patient = patientService.findById(id);
        patient.setStatus(false);
        patientService.savePatient(patient);
        return "redirect:/admin/patients";
    }

    @GetMapping("/enable/{id}")
    public String enablePatient(@PathVariable Integer id) {
        Patient patient = patientService.findById(id);
        patient.setStatus(true);
        patientService.savePatient(patient);
        return "redirect:/admin/patients";
    }
}

