package com.clinicmanagement.clinic.controller;

import com.clinicmanagement.clinic.Entities.*;
import com.clinicmanagement.clinic.config.VNPayService;
import com.clinicmanagement.clinic.service.*;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.time.LocalDate;
import java.time.LocalTime;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

@Controller
@RequestMapping("/vnpay")
public class VNPayController {
    @Autowired
    private VNPayService vnPayService;
    private static final Logger logger = LoggerFactory.getLogger(VNPayController.class);

    @Autowired
    private AppointmentService _appointmentService;

    @Autowired
    private PaymentService _paymentService;

    @Autowired
    private PatientService _patientService;

    @Autowired
    private DoctorService _doctorService;

    @Autowired
    private ServicesService _servicesService;

    @Autowired
    private appointment_serviceService appointment_serviceService;


    @PostMapping("/submitOrder")
    public String submidOrder(@RequestParam("amount") int orderTotal,
                              @RequestParam("orderInfo") String orderInfo,
                              HttpServletRequest request) {
        logger.info("Received amount: " + orderTotal);
        logger.info("Received orderInfo: " + orderInfo);
        System.out.println("Received orderInfo: " + orderInfo);

        String baseUrl = request.getScheme() + "://" + request.getServerName() + ":" + request.getServerPort();
        logger.info("Base URL: " + baseUrl);

        String vnpayUrl = vnPayService.createOrder(orderTotal, orderInfo, baseUrl);
        logger.info("Generated VNPay URL: " + vnpayUrl);

        if (vnpayUrl == null || vnpayUrl.isEmpty()) {
            return "redirect:/error?message=Invalid VNPay URL";
        }

        return String.format("redirect:%s", vnpayUrl);

    }

    @GetMapping("/vnpay-payment")
    public String GetMapping(HttpServletRequest request, Model model) {
        int paymentStatus = vnPayService.orderReturn(request);

        String orderInfo = request.getParameter("vnp_OrderInfo");
        String paymentTime = request.getParameter("vnp_PayDate");
        String transactionId = request.getParameter("vnp_TransactionNo");
        String totalPrice = request.getParameter("vnp_Amount");

        model.addAttribute("orderId", orderInfo);
        model.addAttribute("totalPrice", totalPrice);
        model.addAttribute("paymentTime", paymentTime);
        model.addAttribute("transactionId", transactionId);

        if (paymentStatus == 1) {
            try {
                handlePaymentSuccess(orderInfo, totalPrice); // Xử lý thanh toán thành công
            } catch (RuntimeException e) {
                e.printStackTrace();
                return "booking/orderfail"; // Chuyển tới trang lỗi nếu có exception
            }
        }

        return paymentStatus == 1 ? "booking/ordersuccess" : "booking/orderfail";
    }

    private void handlePaymentSuccess(String orderInfo, String totalPrice) {
        // Phân tích chuỗi orderInfo
        String[] parts = orderInfo.split("-");
        String[] serviceIds = parts[0].split(",");
        List<Integer> serviceIdList = Arrays.stream(serviceIds).map(Integer::parseInt).collect(Collectors.toList());

        LocalDate appointmentDate = LocalDate.parse(parts[1] + "-" + parts[2] + "-" + parts[3]);
        LocalTime startTime = LocalTime.parse(parts[4].replace("h", ":"));
        LocalTime endTime = LocalTime.parse(parts[5].replace("h", ":"));

        Integer patientId = Integer.parseInt(parts[6]);

        // Tìm bác sĩ
        Doctor availableDoctor = _doctorService.findFirstAvailableDoctor(appointmentDate, startTime, endTime)
                .orElseThrow(() -> new RuntimeException("No available doctor found"));

        // Tạo Appointment
        Appointment appointment = new Appointment();
        appointment.setPatient(_patientService.findById(patientId));
        appointment.setDoctor(availableDoctor);
        appointment.setAppointmentDate(appointmentDate);
        appointment.setAppointmentTime(startTime);
        appointment.setStatus("CONFIRMED");
        Appointment savedAppointment = _appointmentService.save(appointment);

        // Tạo AppointmentService
        List<appointment_service> appointmentServices = serviceIdList.stream()
                .map(serviceId -> {
                    Services service = _servicesService.findById(serviceId);
                    appointment_service appointmentService = new appointment_service();
                    appointmentService.setAppointment_id(savedAppointment);
                    appointmentService.setServices(service);
                    appointmentService.setNote("Tự động thêm");
                    return appointmentService;
                })
                .collect(Collectors.toList());
        appointment_serviceService.saveAll(appointmentServices);

        // Tạo Payment
        payment payment = new payment();
        payment.setAppointment(savedAppointment);
        payment.setPaymentDate(LocalDate.now());
        payment.setTotalAmount(Double.parseDouble(totalPrice) / 100); // Chuyển từ đơn vị VNĐ nhỏ
        payment.setPaymentMethod("VNPay");
        payment.setStatus("SUCCESS");
        _paymentService.save(payment);
    }


    private Doctor findAvailableDoctor(LocalDate date, LocalTime startTime, LocalTime endTime) {
        return _doctorService.findFirstAvailableDoctor(date, startTime, endTime)
                .orElseThrow(() -> new RuntimeException("No available doctor found"));
    }

}