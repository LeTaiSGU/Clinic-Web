package com.clinicmanagement.clinic.controller;

import com.clinicmanagement.clinic.Entities.*;
import com.clinicmanagement.clinic.dto.ChangePasswordDTO;
import com.clinicmanagement.clinic.exception.AppException;
import com.clinicmanagement.clinic.exception.ErrorCode;
import com.clinicmanagement.clinic.repository.UserRepository;
import com.clinicmanagement.clinic.service.AppointmentService;
import com.clinicmanagement.clinic.service.PatientService;
import com.clinicmanagement.clinic.service.PaymentService;
import com.clinicmanagement.clinic.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.security.Principal;
import java.util.HashMap;
import java.util.List;
import java.util.Map;


@Controller
@RequestMapping("/information")
public class InformationController {
    @Autowired
    private AppointmentService _appointmentService;

    @Autowired
    private UserRepository _userRepository;

    @Autowired
    private PatientService _patientService;

    @Autowired
    private PaymentService _paymentService;

    @Autowired
    private UserService _userService;

    //========================================APPOINTMENT===========================================

    @GetMapping("/appointment")
    public String getAppointmentsByPatient(Model model) {
        var context = SecurityContextHolder.getContext();
        String username = context.getAuthentication().getName();

        // Tìm Useracount dựa trên username
        Useraccount user = _userRepository.findByUsername(username)
                .orElseThrow(() -> new AppException(ErrorCode.USER_NOT_EXISTED));

        // Lấy danh sách các cuộc hẹn của bệnh nhân
        List<Appointment> appointments = _appointmentService.getAppointmentsByPatient(user.getPatient());

        // Tạo một danh sách để lưu dịch vụ cho từng cuộc hẹn
        Map<Integer, List<appointment_service>> appointmentServicesMap = new HashMap<>();

        // Lặp qua từng cuộc hẹn để lấy dịch vụ
        for (Appointment appointment : appointments) {
            List<appointment_service> services = _appointmentService.getServiceByAppointment(appointment);
            appointmentServicesMap.put(appointment.getId(), services);
        }

        // Thêm danh sách cuộc hẹn và dịch vụ vào model
        model.addAttribute("appointments", appointments);
        model.addAttribute("appointmentServicesMap", appointmentServicesMap);
        model.addAttribute("user", user);

        System.out.println("Patient ID: " + username);
        return "information/appointment/index"; // Trả về view
    }



    /*@GetMapping("/search")
    public String searchAppointments(@RequestParam String keyword, Model model) {
        List<Appointment> appointments = _appointmentService.searchAppointments(keyword);
        model.addAttribute("appointments", appointments);
        model.addAttribute("keyword", keyword);  // Thêm keyword vào model
        return "information/appointment/index";
    }*/

    @GetMapping("/appointment/search")
    public String searchAppointments(
            @RequestParam(required = false) String keyword,
            Model model,
            Principal principal
    ) {
        // Lấy thông tin người dùng hiện tại
        var context = SecurityContextHolder.getContext();
        String username = context.getAuthentication().getName();

        Useraccount user = _userRepository.findByUsername(username)
                .orElseThrow(() -> new AppException(ErrorCode.USER_NOT_EXISTED));

        // Thực hiện tìm kiếm
        List<Appointment> appointments = _appointmentService.searchAppointments(keyword);

        // Tạo map dịch vụ cho từng cuộc hẹn
        Map<Integer, List<appointment_service>> appointmentServicesMap = new HashMap<>();
        for (Appointment appointment : appointments) {
            List<appointment_service> services =
                    _appointmentService.getServiceByAppointment(appointment);
            appointmentServicesMap.put(appointment.getId(), services);
        }

        // Thêm dữ liệu vào model
        model.addAttribute("appointments", appointments);
        model.addAttribute("appointmentServicesMap", appointmentServicesMap);
        model.addAttribute("user", user);
        model.addAttribute("keyword", keyword);

        return "information/appointment/index";
    }


    @PostMapping("/appointment/cancel")
    public String cancelAppointment(@RequestParam("id") Integer appointmentId,
                                    RedirectAttributes redirectAttributes) {

        Appointment appointment = _appointmentService.findById(appointmentId);


        try {
            // Tìm appointment cần hủy

            // Kiểm tra nếu appointment còn hiệu lực để hủy
            if (appointment != null && appointment.getStatus() != "0") {
                // Cập nhật trạng thái thành 0 (đã hủy)
                appointment.setStatus("0");
                _appointmentService.save(appointment);

                // Thêm thông báo thành công
                redirectAttributes.addFlashAttribute("successMessage", "Hủy lịch khám thành công");
            } else {
                // Thêm thông báo lỗi nếu không thể hủy
                redirectAttributes.addFlashAttribute("errorMessage", "Không thể hủy lịch khám này");
            }

            // Quay lại trang danh sách với các thông tin đã lưu
            return "redirect:/information/appointment/" + appointment.getPatient().getId();
        } catch (Exception e) {
            // Xử lý nếu có lỗi
            redirectAttributes.addFlashAttribute("errorMessage", "Có lỗi xảy ra khi hủy lịch");
            return "redirect:/information/appointment/" + appointment.getPatient().getId();
        }
    }



    //========================================History===========================================

    @GetMapping("/history/{patientId}")
    public String GetPatients(@PathVariable Integer patientId, Model model) {
        try {

            var context = SecurityContextHolder.getContext();
            String username = context.getAuthentication().getName();

            Useraccount user = _userRepository.findByUsername(username)
                    .orElseThrow(() -> new AppException(ErrorCode.USER_NOT_EXISTED));

            List<payment> payments = _paymentService.getPaymentsByPatient(patientId);
            model.addAttribute("payments", payments);
            model.addAttribute("user", user);
            return "information/history/index";
        } catch (Exception e) {
            e.printStackTrace();  // Log exception for debugging
            model.addAttribute("errorMessage", "An error occurred while fetching patients.");
            return "error";
        }
    }

    @GetMapping("/history/search/{patientId}")
    public String showPaymentHistory(
            @PathVariable int patientId,
            @RequestParam(required = false) String keyword,
            Model model
    ) {

        var context = SecurityContextHolder.getContext();
        String username = context.getAuthentication().getName();

        Useraccount user = _userRepository.findByUsername(username)
                .orElseThrow(() -> new AppException(ErrorCode.USER_NOT_EXISTED));

        List<payment> payments;

        if (keyword != null && !keyword.trim().isEmpty()) {
            payments = _paymentService.searchPayments(keyword, patientId);
        } else {
            payments = _paymentService.findByPatientId(patientId);
        }

        model.addAttribute("user", user);
        model.addAttribute("payments", payments);
        return "information/history/index";
    }


    //========================================PROFILE===========================================


    @GetMapping("/userProfile/{patientId}")
    public String getUserProfileByPatient (@PathVariable Integer patientId, Model model) {
        var context = SecurityContextHolder.getContext();
        String username = context.getAuthentication().getName();

        // Tìm Useracount dựa trên username
        Useraccount user = _userRepository.findByUsername(username)
                .orElseThrow(() -> new AppException(ErrorCode.USER_NOT_EXISTED));

        Patient patient = user.getPatient();

        if (patient == null) {
            System.out.println("Patient ID: " + patientId);
        }

        // Kiểm tra xem patientId có khớp với patient từ user không
        if (!patient.getId().equals(patientId)) {
            System.out.println("Patient ID: " + patientId);
        }

        // Thêm thông tin bệnh nhân vào model
        model.addAttribute("patient", patient);
        model.addAttribute("user", user);
        return "information/userProfile/index";
    }

    @GetMapping("/userProfile/detail/{patientId}")
    public String showEditProfileForm(@PathVariable Integer patientId, Model model) {
        // Lấy thông tin patient từ user hiện tại
        var context = SecurityContextHolder.getContext();
        String username = context.getAuthentication().getName();

        Useraccount user = _userRepository.findByUsername(username)
                .orElseThrow(() -> new AppException(ErrorCode.USER_NOT_EXISTED));

        Patient patient = user.getPatient();

        // Kiểm tra quyền truy cập
        if (patient == null || !patient.getId().equals(patientId)) {
            System.out.println("Patient ID: " + patientId);
        }
        System.out.println("DOB: " + patient.getDob());
        // Thêm patient vào model để điền dữ liệu vào form
        model.addAttribute("patient", patient);
        model.addAttribute("user", user);

        return "information/userProfile/detail"; // Trang chỉnh sửa
    }

    @PostMapping("/userProfile/update")
    public String updateUserProfile(@ModelAttribute Patient patient,
                                    RedirectAttributes redirectAttributes) {
        try {
            Patient existingPatient = _patientService.findById(patient.getId());

            Patient patientWithEmail = _patientService.findByEmail(patient.getEmail());

            if (patientWithEmail != null && !patientWithEmail.getId().equals(patient.getId())) {
                redirectAttributes.addFlashAttribute("errorMessage", "Email đã được sử dụng bởi người khác");
                return "redirect:/information/userProfile/detail/" + patient.getId();
            }

            existingPatient.setFullName(patient.getFullName());
            existingPatient.setPhone(patient.getPhone());
            existingPatient.setEmail(patient.getEmail());
            existingPatient.setDob(patient.getDob());
            existingPatient.setAddress(patient.getAddress());

            _patientService.savePatient(existingPatient);
            redirectAttributes.addFlashAttribute("errorMessage", "Cập nhật hồ sơ thành công");

            return "redirect:/information/userProfile/" + existingPatient.getId();

        } catch (Exception e) {
            // Xử lý lỗi
            redirectAttributes.addFlashAttribute("errorMessage", "Có lỗi xảy ra khi cập nhật");
            return "redirect:/information/userProfile/edit/" + patient.getId();
        }
    }

    @GetMapping("/account/{patientId}")
    public String getUserAccount (@PathVariable Integer patientId, Model model) {
        var context = SecurityContextHolder.getContext();
        String username = context.getAuthentication().getName();

        // Tìm Useracount dựa trên username
        Useraccount user = _userRepository.findByUsername(username)
                .orElseThrow(() -> new AppException(ErrorCode.USER_NOT_EXISTED));

        Patient patient = user.getPatient();

        if (patient == null) {
            System.out.println("Patient ID: " + patientId);
        }

        // Kiểm tra xem patientId có khớp với patient từ user không
        if (!patient.getId().equals(patientId)) {
            System.out.println("Patient ID: " + patientId);
        }

        // Thêm thông tin bệnh nhân vào model
        model.addAttribute("patient", patient);
        model.addAttribute("user", user);

        model.addAttribute("changePasswordDTO", new ChangePasswordDTO());

        return "information/account/index";
    }

    @PostMapping("/account/change-password/{patientId}")
    public String changePassword(
            @PathVariable Integer patientId,
            @ModelAttribute ChangePasswordDTO changePasswordDTO,
            RedirectAttributes redirectAttributes,
            Principal principal
    ) {


        System.out.println("Received PatientId: " + patientId);
        System.out.println("Current Password: " + changePasswordDTO.getCurrentPassword());
        System.out.println("New Password: " + changePasswordDTO.getNewPassword());
        System.out.println("Confirm Password: " + changePasswordDTO.getConfirmNewPassword());

        try {
            _userService.changePassword(changePasswordDTO);
            redirectAttributes.addFlashAttribute("successMessage", "Thay đổi mật khẩu thành công");

            return "redirect:/information/account/" + patientId;
        } catch (AppException e) {
            // Xử lý các ngoại lệ
            redirectAttributes.addFlashAttribute("errorMessage", e.getMessage());
            return "redirect:/information/account/" + patientId;
        }
    }























    //Viết add controller ở đây nha hiệp
    @PostMapping("/cancel")
    public String cancelAppointment(@RequestParam("id") int id) {
        try {
            _appointmentService.cancelAppointment(id);
            return "redirect:/information/appointment";
        } catch (Exception e) {
            return "error";
        }
    }

    /*@GetMapping("/profile")
    public String GetPatients(Model model) {
        try {
            List<Patient> patients = _patientService.getAllPatients();
            model.addAttribute("appointments", appointments);
            return "information/appointment/index";
        } catch (Exception e) {
            e.printStackTrace();  // Log exception for debugging
            model.addAttribute("errorMessage", "An error occurred while fetching appointments.");
            return "error";
        }
    }*/
}
