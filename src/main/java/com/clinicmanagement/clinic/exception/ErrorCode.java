package com.clinicmanagement.clinic.exception;

public enum ErrorCode {

    INVALID_KEY(1003,"Invalid key"),
    UNCATEGORIZED_EXCEPTION(5050,"Uncategorized Error"),
    USER_EXISTED(1001,"User existed"),
    USERNAME_INVALID(1002,"Username phải có ít nhất 8 kí tự"),
    PASS_INVALID(1003,"Password phải ít nhất 8 kí tự"),
    USER_NOT_EXISTED(1004,"User not existed"),
    UNAUTHENICATED(1005,"Sai mật khẩu"),
    EXISTED(1006,"Đã tồn tại"),
    INVALID_PASSWORD(1007,"Mật khẩu không đúng"),
    PASSWORD_NOT_MATCH(1008,"Mật khẩu xác nhận không khớp"),
    PASSWORD_TOO_SHORT(1009,"Mật khẩu phải có ít nhất 8 ký tự"),
    USER_ACCOUNT_INACTIVE(1010,"Tài khoản đang tạm khóa");

    ErrorCode(int code,String message){
        this.code = code;
        this.message = message;
    }

    private int code;
    private String message;

    public int getCode() {
        return code;
    }

    public String getMessage() {
        return message;
    }
}
