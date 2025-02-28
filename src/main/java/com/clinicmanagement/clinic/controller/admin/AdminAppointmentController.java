package com.clinicmanagement.clinic.controller.admin;

import com.clinicmanagement.clinic.Entities.Appointment;
import com.clinicmanagement.clinic.Entities.Doctor;
import com.clinicmanagement.clinic.service.AppointmentService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Controller
@RequestMapping("/admin/appointments")
public class AdminAppointmentController {

@Autowired
AppointmentService appointmentService;

    @GetMapping
    public String getAllAppointments(
            @RequestParam(required = false) String doctorName,
            @RequestParam(required = false) String patientName,
            @RequestParam(required = false) String appointmentDate,
            Model model) {

        System.out.println("Search appointments in memory");

        // Lấy tất cả các cuộc hẹn
        List<Appointment> appointments = appointmentService.getAllAppointments();

        // Lọc dữ liệu theo điều kiện
        List<Appointment> filteredAppointments = appointments.stream()
                .filter(appointment -> doctorName == null || doctorName.isEmpty() ||
                        appointment.getDoctor().getFullName().toLowerCase().contains(doctorName.toLowerCase()))
                .filter(appointment -> patientName == null || patientName.isEmpty() ||
                        appointment.getPatient().getFullName().toLowerCase().contains(patientName.toLowerCase()))
                .filter(appointment -> appointmentDate == null || appointmentDate.isEmpty() ||
                        appointment.getAppointmentDate().toString().equals(appointmentDate))
                .toList();

        // Chuẩn bị dữ liệu để hiển thị
        List<Map<String, Object>> appointmentDetails = filteredAppointments.stream().map(appointment -> {
            Map<String, Object> detail = new HashMap<>();
            detail.put("id", appointment.getId());
            detail.put("appointmentDate", appointment.getAppointmentDate());
            detail.put("appointmentTime", appointment.getAppointmentTime());
            detail.put("patientName", appointment.getPatient().getFullName());
            detail.put("doctorName", appointment.getDoctor().getFullName());
            detail.put("services", appointment.getAppointmentServices().stream()
                    .map(apptService -> apptService.getServices().getServiceName()).toList());
            detail.put("status", appointment.getStatus());
            return detail;
        }).toList();

        model.addAttribute("appointmentDetails", appointmentDetails);
        return "admin/appointment/appointment";
    }
}
