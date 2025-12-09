# Hướng dẫn Di chuyển Dự án (Bao gồm Database và Dữ liệu)

Để di chuyển toàn bộ dự án sang một máy khác, hãy làm theo các bước sau:

---

### **Bước 1: Trên Máy Cũ **

Mục tiêu là đóng gói database và các file cần thiết.

1.  **Dừng ứng dụng:** Mở terminal trong thư mục `CheckingOrders-V2` và chạy lệnh để đảm bảo dữ liệu không bị thay đổi trong quá trình sao lưu.
    ```bash
    docker-compose down
    ```
2.  ** Database:** Chạy lệnh sau để đóng gói volume `mongodb_data` thành một file `mongodb_backup.tar.gz`. Lệnh này sẽ tạo file backup ngay trong thư mục `CheckingOrders-V2`.
    ```bash
    # Windows:
    docker run --rm -v mongodb_data:/data -v ${PWD}:/backup ubuntu tar czvf /backup/mongodb_backup.tar.gz -C /data .

3.  **Nén thư mục `uploads`:**
    ```bash
    tar -czvf uploads_backup.tar.gz -C ./uploads .
    ```

4.  **Lưu file môi trường:** Dự án của bạn rất có thể có một file `.env` chứa các cấu hình quan trọng (ví dụ: mật khẩu, API keys). Hãy sao chép file này ra một nơi an toàn vì nó thường không được lưu trên Git.

Sau bước này, bạn sẽ có 2 file quan trọng trong thư mục dự án: `mongodb_backup.tar.gz` và `uploads_backup.tar.gz`, cùng với file `.env` đã lưu.

---

### **Bước 2: Di Chuyển File**

Chuyển 2 file backup (`mongodb_backup.tar.gz`, `uploads_backup.tar.gz`) và file `.env` sang máy mới. Bạn có thể dùng USB, Google Drive, hoặc truyền qua mạng nội bộ.

---

### **Bước 3: Trên Máy Mới**

1.  **Clone mã nguồn:**
    ```bash
    git clone 
    ```
    Sau đó, đặt các file backup và file `.env` vào trong thư mục `CheckingOrders-V2` vừa clone về.

2.  **Phục hồi (Restore) Database:**
    *   Đầu tiên, tạo một volume trống với đúng tên `mongodb_data`:
        ```bash
        docker volume create mongodb_data
        ```
    *   Sau đó, giải nén file backup vào volume vừa tạo:
        ```bash
        # Đối với PowerShell trên Windows:
        docker run --rm -v mongodb_data:/data -v ${PWD}:/backup ubuntu tar xzvf /backup/mongodb_backup.tar.gz -C /data

        # Đối với bash trên Linux/macOS:
        docker run --rm -v mongodb_data:/data -v $(pwd):/backup ubuntu tar xzvf /backup/mongodb_backup.tar.gz -C /data
        ```

3.  **Phục hồi thư mục `uploads`:**
    *   Nếu thư mục `uploads` chưa có, hãy tạo nó trước: `mkdir uploads`
    *   Giải nén file backup vào đó:
        ```bash
        tar -xzvf uploads_backup.tar.gz -C ./uploads
        ```

4.  **Khởi động lại ứng dụng:**
    Cuối cùng, build và chạy lại toàn bộ hệ thống với `docker-compose`.
    ```bash
    docker-compose up -d --build
    ```

Sau khi hoàn tất, ứng dụng trên máy mới sẽ có đầy đủ mã nguồn và toàn bộ dữ liệu giống hệt như trên máy cũ.
