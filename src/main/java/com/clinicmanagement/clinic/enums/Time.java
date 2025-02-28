package com.clinicmanagement.clinic.enums;

public enum Time {
    SLOT_08_12("08:00", "12:00"),
    SLOT_13_17("13:00", "17:00"),
    SLOT_18_21("18:00", "21:00");

    private final String startTime;
    private final String endTime;

    Time(String startTime, String endTime) {
        this.startTime = startTime;
        this.endTime = endTime;
    }

    public String getStartTime() {
        return startTime;
    }

    public String getEndTime() {
        return endTime;
    }

    public String getDisplayTime() {
        return startTime + "-" + endTime;
    }
}

