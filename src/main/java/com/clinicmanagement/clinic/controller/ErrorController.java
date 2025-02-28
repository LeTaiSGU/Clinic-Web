package com.clinicmanagement.clinic.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class ErrorController {
    @GetMapping("/access-denied")
    public String accessDenied() {
        return "/ErrorPage/accessdined"; // trả về trang access-denied.html
    }
}
