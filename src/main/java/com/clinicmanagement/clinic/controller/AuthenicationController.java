package com.clinicmanagement.clinic.controller;

import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import lombok.extern.slf4j.Slf4j;
//import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping("/auth")
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE,makeFinal = true)
@Slf4j
public class AuthenicationController {

//    AuthenicationService authenicationService;
//
//    @PostMapping("/login")
//    ApiResponse<AuthenicationResponse> authenicate(@RequestBody AuthenicationRequest request) {
//        var result = authenicationService.authenicate(request);
//        return ApiResponse.<AuthenicationResponse>builder()
//                .result(result)
//                .build();
//    }

}
