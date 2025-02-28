package com.clinicmanagement.clinic.service;

import com.clinicmanagement.clinic.Entities.Appointment;
import com.clinicmanagement.clinic.Entities.Patient;
import com.clinicmanagement.clinic.Entities.appointment_service;
import com.clinicmanagement.clinic.repository.AppointmentRepository;
import jakarta.transaction.Transactional;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

import org.slf4j.Logger;

@Service
public class AppointmentService {
    @Autowired
    private AppointmentRepository _appointmentRepository;

    @Autowired
    private static final Logger logger = LoggerFactory.getLogger(AppointmentService.class);

    public List<Appointment> getAppointmentsByPatient(Patient patient) {
        return _appointmentRepository.findByPatient(patient);
    }

    public List<appointment_service> getServiceByAppointment(Appointment appointment) {
        return appointment.getAppointmentServices();
    }
    public List<Appointment> searchAppointments(String keyword) {
        // Xử lý trường hợp keyword rỗng hoặc null
        if (keyword == null || keyword.trim().isEmpty()) {
            return _appointmentRepository.findAll();
        }

        // Chuẩn hóa keyword
        String normalizedKeyword = keyword.trim();

        // Thực hiện tìm kiếm
        List<Appointment> results = _appointmentRepository.searchAppointments(normalizedKeyword);

        System.out.println("==== Thông Tin Tìm Kiếm ====");
        System.out.println("Từ khóa: " + normalizedKeyword);
        System.out.println("Số lượng kết quả: " + results.size());
        System.out.println("============================");

        return results;
    }

    public Appointment findById(Integer id) {
        return _appointmentRepository.findById(id).orElse(null);
    }


    public Appointment save(Appointment appointment) {
        return _appointmentRepository.save(appointment);
    }





    @Transactional
    public List<Appointment> getAllAppointments() {
        List<Appointment> appointments = _appointmentRepository.findAll();
        appointments.forEach(appointment -> {
            // Đảm bảo các AppointmentServices được tải trước khi trả về
            appointment.getAppointmentServices().size();
        });
        return appointments;
    }




    /*public List<Appointment> searchAppointments(String keyword) {
        return _appointmentRepository.searchAppointments(keyword);
    }*/

    public void addAppointment(Appointment appointment) {
        try {
            _appointmentRepository.save(appointment);
        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException("Có lỗi xảy ra");
        }
    }


    public void cancelAppointment(int id) {
        Optional<Appointment> appointmentOptional  = _appointmentRepository.findById(id);
        if(appointmentOptional .isPresent()) {
            Appointment appointment = appointmentOptional.get();
            appointment.setStatus("Đã hủy");
            _appointmentRepository.save(appointment);
        } else {
            throw new RuntimeException("Không tìm thấy Id");
        }

    }



}
