function showDetails(element) {

    document.getElementById('emptyMessage').style.display = 'none';
    document.getElementById('appointmentDetailForm').style.display = 'block';
    // Lấy hàng (tr) chứa link (a) vừa được click
    const row = element.closest('tr');

    // Lấy dữ liệu từ các thuộc tính data-* của hàng
    const appointmentId = row.getAttribute('data-id');
    const appointmentDate = row.getAttribute('data-date');
    const appointmentTime = row.getAttribute('data-time');
    const doctorName = row.getAttribute('data-doctor');
    const status = row.getAttribute('data-status');

    // Lấy danh sách dịch vụ liên quan
    const services = row.querySelectorAll('td div span');
    let serviceNames = [];
    services.forEach(service => {
        serviceNames.push(service.textContent);  // Lấy tên dịch vụ
    });
    const serviceName = serviceNames.join(', ');

    // Điền dữ liệu vào form chi tiết
    document.getElementById('detailId').value = appointmentId;
    document.getElementById('detaiDate').value = appointmentDate;
    document.getElementById('detaiTime').value = appointmentTime;
    document.getElementById('detailDoctor').value = doctorName;
    document.getElementById('detailStatus').value = status;
    document.getElementById('detailService').value = serviceName;
}