# WIP!

# Sisop-FP-2024-MH-IT27
Anggota Kelompok :
|  NRP|Nama Anggota  |
|--|--|
|5027231079|Harwinda|
|5027221058|Irfan Qobus Salim|
|5027231038|Dani Wahyu Anak Ary|

# Pendahuluan
Dalam final project praktikum DiscorIT, kami diminta untuk menyelesaikan implementasi sebuah sistem chat berbasis socket yang terdiri dari tiga file utama yaitu discorit.c (client untuk mengirim request), server.c (server yang menerima dan merespon request), dan monitor.c (client untuk menampilkan chat secara real-time).

Program ini memungkinkan user untuk berkomunikasi secara real-time melalui channel dan room yang dapat dikelola oleh user dengan peran tertentu. User harus melakukan autentikasi sebelum dapat mengakses fitur-fitur yang ada. Keamanan juga dijamin dengan menggunakan bcrypt untuk enkripsi password dan key channel.

# Authentikasi

## Register/Login ke Server
Berikut adalah penjelasan dan contoh cara kerja program ini untuk mengirim perintah register atau login ke server.

### Penjelasan

1. **Membaca Argumen Command Line**: Program ini menerima argumen dari command line. Argumen pertama menentukan apakah pengguna ingin mendaftar (register) atau masuk (login). Argumen kedua adalah username, dan argumen keempat adalah password. Argumen ketiga adalah `-p` yang menunjukkan bahwa argumen berikutnya adalah password.

2. **Membuat Socket**: Program membuat sebuah socket untuk berkomunikasi dengan server.

3. **Menentukan Alamat Server**: Program menentukan alamat IP dan port server yang akan dihubungi.

4. **Menghubungkan ke Server**: Program mencoba untuk menghubungkan socket ke server.

5. **Mengirim Perintah ke Server**: Bergantung pada perintah yang diberikan (`REGISTER` atau `LOGIN`), program akan memanggil fungsi `register_user` atau `login_user` untuk mengirimkan data ke server melalui socket.

6. **Menutup Koneksi**: Setelah mengirim perintah, program menutup koneksi socket.

**Kode**:
<details>
<summary><h3>Klik untuk selengkapnya</h3>></summary>

```c
 if (argc < 4) {
        fprintf(stderr, "Usage: %s REGISTER|LOGIN username -p password\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    int sock = 0;
    struct sockaddr_in serv_addr;
    char buffer[1024] = {0};

    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);

    if (inet_pton(AF_INET, IP, &serv_addr.sin_addr) <= 0) {
        perror("Invalid address/ Address not supported");
        exit(EXIT_FAILURE);
    }

    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("Connection failed");
        exit(EXIT_FAILURE);
    }

    printf("Connected to server\n");

    if (strcmp(argv[1], "REGISTER") == 0) {
        register_user(sock, argv[2], argv[4]);
    } else if (strcmp(argv[1], "LOGIN") == 0) {
        login_user(sock, argv[2], argv[4]);
    } else {
        fprintf(stderr, "Invalid command\n");
        exit(EXIT_FAILURE);
    }

    close(sock);
    return 0;
}
```
</details>

### Contoh Penggunaan

Untuk mendaftar (register), jalankan program ini dengan perintah:

```
./program REGISTER username -p password
```

Untuk masuk (login), jalankan program ini dengan perintah:

```
./program LOGIN username -p password
```

Program ini akan mengirimkan string yang diformat ke server sesuai dengan perintah yang diberikan (`REGISTER` atau `LOGIN`). Server kemudian akan memproses perintah tersebut sesuai dengan implementasi yang ada di sisi server.

### Handling Buffer yang Dikirim Client
Fungsi `handle_client` memang berperan penting dalam menangani buffer yang dikirim oleh klien untuk proses registrasi (`REGISTER`) atau masuk (`LOGIN`). Berikut penjelasan lebih rinci disertai contoh bagaimana fungsi ini bekerja untuk kedua proses tersebut:

### Penanganan Buffer dalam `handle_client`
<details>
<summary><h3>Klik Untuk Selengkapnya</h3>></summary>
 
1. **Menerima Data dari Klien**:
    - Fungsi `recv()` digunakan untuk membaca data dari klien melalui socket dan menyimpannya dalam buffer `buffer` dengan ukuran maksimum `MAX_BUFFER`.
   
    ```c
    #define MAX_BUFFER 1024
    char buffer[MAX_BUFFER];
    int n;

    while ((n = recv(client_socket, buffer, sizeof(buffer), 0)) > 0) {
        buffer[n] = '\0';  // Menandai akhir string
        printf("Client: %s\n", buffer);
    ```

2. **Memisahkan Perintah dari Buffer**:
    - Fungsi `strtok()` digunakan untuk memisahkan perintah dari buffer yang diterima. Perintah pertama yang dipisahkan akan dibandingkan dengan string "REGISTER" atau "LOGIN".
    
    ```c
    char *command = strtok(buffer, " ");
    if (strcmp(command, "REGISTER") == 0) {
        // Penanganan registrasi
    } else if (strcmp(command, "LOGIN") == 0) {
        // Penanganan login
    }
    ```
3. **Menangani Registrasi**:
    - Jika perintah adalah `REGISTER`, fungsi `handle_register` dipanggil untuk memproses registrasi klien dengan data yang diterima. Data `username` dan `password` diekstrak dari buffer dan diteruskan ke fungsi `register_user`.

    ```c
    if (strcmp(command, "REGISTER") == 0) {
        char *username = strtok(NULL, " ");
        strtok(NULL, " ");  // Lewati "-p"
        char *password = strtok(NULL, " ");
        handle_register(username, password, client_socket);
    }
    ```

    **Contoh `handle_register`**:

    ```c
    void handle_register(const char *username, const char *password, int client_socket) {
        // Implementasi fungsi registrasi
        register_user(username, password, client_socket);
    }
    ```
    
4. **Menangani Login**:
    - Jika perintah adalah `LOGIN`, fungsi `handle_login` dipanggil untuk memproses login klien dengan data yang diterima. Data `username` dan `password` diekstrak dari buffer dan diteruskan ke fungsi `login_user`.

    ```c
    if (strcmp(command, "LOGIN") == 0) {
        char *username = strtok(NULL, " ");
        strtok(NULL, " ");  // Lewati "-p"
        char *password = strtok(NULL, " ");
        handle_login(username, password, client_socket);
    }
    ```

    **Contoh `handle_login`**:

    ```c
    void handle_login(const char *username, const char *password, int client_socket) {
        // Implementasi fungsi login
        login_user(username, password, client_socket);
    }
    ```

5. **Mereset Buffer**:
    - Setelah selesai memproses perintah, buffer direset menggunakan `memset()` untuk persiapan menerima data selanjutnya dari klien.

    ```c
    memset(buffer, 0, sizeof(buffer));
    ```

6. **Menutup Koneksi**:
    - Ketika klien menutup koneksi, `handle_client` menutup socket yang terkait dan membebaskan memori yang dialokasikan untuk struktur data klien.

    ```c
    close(client_socket);
    ```
</details>

### Contoh Keseluruhan `handle_client`
<details>
<summary><h3>Klik Untuk Selengkapnya</h3>></summary>
 
   ```c
    void handle_client(int client_socket) {
    char buffer[MAX_BUFFER];
    int n;

    while ((n = recv(client_socket, buffer, sizeof(buffer), 0)) > 0) {
        buffer[n] = '\0';  // Menandai akhir string
        printf("Client: %s\n", buffer);

        char *command = strtok(buffer, " ");
        if (strcmp(command, "REGISTER") == 0) {
            char *username = strtok(NULL, " ");
            strtok(NULL, " ");  // Lewati "-p"
            char *password = strtok(NULL, " ");
            handle_register(username, password, client_socket);
        } else if (strcmp(command, "LOGIN") == 0) {
            char *username = strtok(NULL, " ");
            strtok(NULL, " ");  // Lewati "-p"
            char *password = strtok(NULL, " ");
            handle_login(username, password, client_socket);
        }

        // Reset buffer untuk menerima data berikutnya
        memset(buffer, 0, sizeof(buffer));
    }

    // Menutup koneksi klien
    close(client_socket);
}
```
</details>

## Fungsi Register di Server
Mari kita lanjutkan dengan mencari dan menjelaskan fungsi registrasi di file `server.c`. Untuk mempermudah penjelasan, saya akan memperlihatkan kode yang relevan serta menjelaskan bagian tersebut secara detail.

**Kode**
<details>
<summary><h3>Klik Untuk Selengkapnya</h3>></summary>
 
```c

int authenticate_user(const char* username, const char* password) {
    // Hard-coded valid credentials
    const char* valid_username = "server";
    const char* valid_password = "server123";

    if (strcmp(username, valid_username) == 0 && strcmp(password, valid_password) == 0) {
        return 1; // Authentication successful
    }
    return 0; // Authentication failed
}

int register_user(const char* username, const char* password) {
    FILE *file = fopen("users.txt", "a");
    if (file == NULL) {
        perror("Could not open users file");
        return 0;
    }
    fprintf(file, "%s %s\n", username, password);
    fclose(file);
    return 1; // Registration successful
}

void create_daemon() {
    pid_t pid;

    // Fork the process
    pid = fork();

    if (pid < 0) {
        exit(EXIT_FAILURE); // Forking failed
    }

    if (pid > 0) {
        exit(EXIT_SUCCESS); // Parent process exits
    }

    // Create a new session
    if (setsid() < 0) {
        exit(EXIT_FAILURE);
    }

    // Fork again to ensure the daemon cannot acquire a controlling terminal
    pid = fork();

    if (pid < 0) {
        exit(EXIT_FAILURE);
    }

    if (pid > 0) {
        exit(EXIT_SUCCESS);
    }

    // Change the working directory to root
    if (chdir("/") < 0) {
        exit(EXIT_FAILURE);
    }

    // Close all open file descriptors
    for (int x = sysconf(_SC_OPEN_MAX); x >= 0; x--) {
        close(x);
    }

    // Open the log file
    open("/tmp/daemon.log", O_RDWR | O_CREAT | O_APPEND, 0600);
    dup(0); // stdin
    dup(0); // stdout
    dup(0); // stderr
}

int main() {
    char username[50];
    char password[50];
    int choice;

    printf("1. Register\n2. Authenticate\nChoose an option: ");
    scanf("%d", &choice);

    printf("Enter username: ");
    scanf("%49s", username);

    printf("Enter password: ");
    scanf("%49s", password);

    if (choice == 1) {
        if (register_user(username, password)) {
            printf("Registration successful!\n");
        } else {
            printf("Registration failed!\n");
        }
    } else if (choice == 2) {
        if (authenticate_user(username, password)) {
            printf("Authentication successful!\n");
            // Create daemon process
            create_daemon();
        } else {
            printf("Authentication failed!\n");
        }
    } else {
        printf("Invalid option!\n");
    }

    return 0;
}
```
</details>

### Penjelasan Fungsi

#### Fungsi `register_user`
- **Deskripsi**: Fungsi ini digunakan untuk mendaftarkan pengguna baru dengan menyimpan username dan password ke dalam file `users.txt`.
- **Parameter**:
  - `const char* username`: Username yang dimasukkan oleh pengguna.
  - `const char* password`: Password yang dimasukkan oleh pengguna.
- **Proses**:
  - Membuka file `users.txt` dalam mode append. Jika file tidak dapat dibuka, menampilkan pesan kesalahan dan mengembalikan `0`.
  - Menulis username dan password ke dalam file dalam format `username password`.
  - Menutup file dan mengembalikan `1` yang menandakan registrasi berhasil.

#### Fungsi `create_daemon`
- **Deskripsi**: Fungsi ini digunakan untuk membuat proses daemon.
- **Proses**:
  - Memanggil `fork` untuk membuat proses anak. Jika fork gagal, proses keluar dengan kode kesalahan.
  - Jika fork berhasil, proses induk keluar.
  - Membuat sesi baru dengan `setsid`.
  - Memanggil `fork` lagi untuk memastikan daemon tidak bisa mendapatkan terminal kontrol.
  - Mengubah direktori kerja ke root dengan `chdir`.
  - Menutup semua deskriptor file yang terbuka.
  - Membuka file log di `/tmp/daemon.log` dan mengarahkan ulang stdin, stdout, dan stderr ke file log tersebut.

#### Fungsi `main`
- **Proses**:
  - Menampilkan pilihan untuk registrasi atau autentikasi.
  - Mengambil input pilihan, username, dan password dari pengguna.
  - Jika pilihan adalah `1`, memanggil `register_user` untuk mendaftarkan pengguna.
  - Jika pilihan adalah `2`, memanggil `authenticate_user` untuk memverifikasi pengguna. Jika autentikasi berhasil, memanggil `create_daemon` untuk membuat proses daemon.


## Fungsi Login di Server
Fungsi `login_user` menangani proses login pengguna dengan memverifikasi username dan password yang diberikan dengan data pengguna yang tersimpan. Jika kredensial valid, pengguna akan berhasil login; jika tidak, pesan kesalahan yang sesuai akan dikirim ke klien.

### Prototipe
```c
void login_user(const char* username, const char* password, int client_socket);
```

### Parameter
- `const char* username`: Username yang diberikan oleh klien.
- `const char* password`: Password yang diberikan oleh klien.
- `int client_socket`: Deskriptor socket untuk komunikasi dengan klien.

### Implementasi
<details>
<summary><h3>Klik Untuk Selengkapnya</h3>></summary>

```c
void login_user(const char* username, const char* password, int client_socket) {
    FILE *file = fopen("users.csv", "r");
    if (file == NULL) {
        perror("Could not open users.csv");
        send_response(client_socket, "Internal server error\n");
        return;
    }

    char line[BUFFER_SIZE];
    int logged_in = 0;
    
    while (fgets(line, sizeof(line), file)) {
        char *id_user = strtok(line, ",");
        char *file_username = strtok(NULL, ",");
        char *file_password = strtok(NULL, ",");
        char *file_role = strtok(NULL, "\n");

        if (strcmp(username, file_username) == 0 && strcmp(password, file_password) == 0) {
            logged_in = 1;
            break;
        }
    }
    
    fclose(file);

    if (logged_in) {
        send_response(client_socket, "Login successful\n");
    } else {
        send_response(client_socket, "Invalid username or password\n");
    }
}
```
</details>

### Penjelasan Kode
1. **Membuka File `users.csv`**: Fungsi mencoba membuka file `users.csv` yang berisi data pengguna. Jika file tidak dapat dibuka, fungsi mengirim pesan kesalahan ke klien dan keluar dari fungsi.
2. **Membaca Data Pengguna**: Fungsi membaca setiap baris dari file `users.csv`. Setiap baris dipecah menjadi beberapa bagian: `id_user`, `file_username`, `file_password`, dan `file_role`.
3. **Memverifikasi Kredensial**: Fungsi memeriksa apakah `username` dan `password` yang diberikan sesuai dengan data dalam file. Jika sesuai, `logged_in` diatur ke 1 dan loop berhenti.
4. **Menutup File**: File `users.csv` ditutup setelah selesai membaca data.
5. **Mengirim Respons ke Klien**: Jika `logged_in` bernilai 1, fungsi mengirim pesan "Login successful" ke klien. Jika tidak, pesan "Invalid username or password" dikirim ke klien.

## Listing

### Channel
Proses listing channel dilakukan dengan membaca file `channel.csv`. Pertama-tama, file `channels.csv` dibuka untuk membaca daftar channel yang tersedia. Jika file tidak dapat dibuka, sistem akan mengirimkan pesan kesalahan kepada client `("Failed to open channel.csv")`. Selanjutnya, sistem melakukan iterasi melalui setiap baris dalam file yang berisi ID dan nama channel. 
**Kode**:
<details>
<summary><h3>Klik untuk selengkapnya</h3>></summary>

```c
void list_channel(int client_socket) {
    FILE *file = fopen("channel.csv", "r");
    if (file == NULL) {
        perror("Failed to open channel.csv");
        exit(EXIT_FAILURE);
    }

    char line[256];
    char response[1024] = "";
    while (fgets(line, sizeof(line), file)) {
        char *token = strtok(line, ",");
        token = strtok(NULL, ","); // channel name
        strcat(response, token);
        strcat(response, " ");
    }

    fclose(file);
    send(client_socket, response, strlen(response), 0);
}
```
</details>

### Room
Proses listing room dilakukan dengan membaca semua folder dalam sebuah channel kecuali folder yang bernama "admin". Sistem akan membuka direktori channel tersebut. Jika direktori tidak bisa dibuka, sistem kembali mengirimkan pesan kesalahan `("Gagal membuka direktori channel")`. Setelah berhasil membuka direktori, sistem melakukan iterasi melalui setiap entry di dalam direktori tersebut, melewatkan entry yang bernama "." dan "..". Sistem juga melewatkan entry dengan nama "admin". Untuk setiap entry yang merupakan direktori, sistem menambahkan nama direktori tersebut ke dalam string respon. Setelah iterasi selesai, direktori ditutup dan sistem mengirimkan string respon yang berisi daftar nama-nama room kepada client. Jika tidak ada room yang ditemukan, sistem mengirimkan pesan bahwa tidak ada room yang ditemukan`("Tidak ada room")`.
**Kode**:
<details>
<summary><h3>Klik untuk selengkapnya</h3>></summary>

```c
void list_room(const char *channel, int client_socket) {
    char channel_dir[BUFFER_SIZE];
    snprintf(channel_dir, sizeof(channel_dir), "%s", channel);

    DIR *dir = opendir(channel_dir);
    if (dir == NULL) {
        perror("Failed to open channel directory");
        send_response(client_socket, "Gagal membuka direktori channel\n");
        return;
    }

    struct dirent *entry;
    char response[BUFFER_SIZE] = "";

    while ((entry = readdir(dir)) != NULL) {
        // Check if the entry is a directory and not "admin", ".", or ".."
        if (entry->d_type == DT_DIR && strcmp(entry->d_name, "admin") != 0 && strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0) {
            strcat(response, entry->d_name);
            strcat(response, " ");
        }
    }

    closedir(dir);

    // If no rooms found, send appropriate response
    if (strlen(response) == 0) {
        send_response(client_socket, "Tidak ada room\n");
    } else {
        send_response(client_socket, response);
    }
}
```
</details>

### Hasil
![image](https://github.com/Daniwahyuaa/readmefpsisop/assets/150106905/dc73fba5-a00b-4eee-b3de-42db9eedd17c)

## Joining

### Channel
**Kode**:
<details>
<summary><h3>Klik untuk selengkapnya</h3>></summary>

```c

void join_channel_without_key(const char *username, const char *channel, int client_socket) {
     // Set the current channel for the client
    pthread_mutex_lock(&clients_mutex);
    strcpy(clients[client_socket].current_channel, channel);
    pthread_mutex_unlock(&clients_mutex);

    char log_message[BUFFER_SIZE];
    snprintf(log_message, sizeof(log_message), "%s joined the channel %s\n", username, channel);
    FILE *log = fopen("users.log", "a");
    if (log != NULL) {
        time_t t = time(NULL);
        struct tm tm = *localtime(&t);
        fprintf(log, "[%02d/%02d/%04d %02d:%02d:%02d] %s\n",
                tm.tm_mday, tm.tm_mon + 1, tm.tm_year + 1900,
                tm.tm_hour, tm.tm_min, tm.tm_sec,
                log_message);
        fclose(log);
    }
    send_response(client_socket, log_message);
}

void join_channel_with_key(const char *username, const char *channel, const char *key, int client_socket) {
    FILE *file = fopen("channel.csv", "r");
    if (file == NULL) {
        perror("Could not open channel.csv");
        send_response(client_socket, "Failed to open channel.csv\n");
        return;
    }

    char line[BUFFER_SIZE];
    int success = 0;
    while (fgets(line, sizeof(line), file)) {
        char *id_channel = strtok(line, ",");
        char *file_channel = strtok(NULL, ",");
        char *file_key = strtok(NULL, "\n");

        printf("Debug: checking channel %s with key %s\n", file_channel, file_key); // Debugging output

        if (strcmp(channel, file_channel) == 0) {
            printf("Debug: channel matched %s\n", file_channel); // Debugging output
            int result = bcrypt_checkpw(key, file_key);
            printf("Debug: bcrypt_checkpw result = %d\n", result); // Debugging output
            if (result == 0) {
                printf("Debug: key matched for channel %s\n", file_channel); // Debugging output
                success = 1;
                break;
            } else {
                printf("Debug: key did not match for channel %s\n", file_channel); // Debugging output
            }
        } else {
            printf("Debug: channel %s did not match %s\n", file_channel, channel); // Debugging output
        }
    }
    fclose(file);

    if (success) {
        join_channel_without_key(username, channel, client_socket);
    } else {
        send_response(client_socket, "Key salah\n");
    }
}

```
</details>

### Room
Sistem akan mengizinkan user untuk bergabung dengan room. Nama room akan disimpan dalam atribut room pada users.log, dan tindakan ini akan dicatat dalam log channel. Sebagai respon, sistem akan mengirim pesan ke user bahwa user telah berhasil bergabung dengan room tersebut `("joined the room")`.
**Kode**:
<details>
<summary><h3>Klik untuk selengkapnya</h3>></summary>

```c
void join_room(const char *username, const char *channel, const char *room, int client_socket) {
    // Set the current room for the client
    pthread_mutex_lock(&clients_mutex);
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i].socket == client_socket) {
            strcpy(clients[i].current_room, room);
            break;
        }
    }
    pthread_mutex_unlock(&clients_mutex);

    // Log the join
    char log_message[BUFFER_SIZE];
    snprintf(log_message, sizeof(log_message), "%s joined the room %s\n", username, room);
    FILE *log = fopen("users.log", "a");
    if (log != NULL) {
        time_t t = time(NULL);
        struct tm tm = *localtime(&t);
        fprintf(log, "[%02d/%02d/%04d %02d:%02d:%02d] %s\n",
                tm.tm_mday, tm.tm_mon + 1, tm.tm_year + 1900,
                tm.tm_hour, tm.tm_min, tm.tm_sec,
                log_message);
        fclose(log);
    }

    // Debug statement to check if the room is set correctly
    printf("Debug: User %s joined room %s in channel %s\n", username, room, channel);
    printf("Debug: clients[%d].current_room = %s\n", client_socket, clients[client_socket].current_room);

    send_response(client_socket, log_message);
}
```
</details>

## Mendapatkan Waktu

### Get Timestamp
Fungsi `get_timestamp()` adalah fungsi pendukung yang esensial dalam sistem chat karena menghasilkan timestamp yang digunakan untuk merekam waktu pengiriman chat dalam room chat. Saat digunakan dalam konteks aplikasi chat, timestamp ini bertindak sebagai penanda waktu yang menunjukkan kapan chat dikirim. Timestamp berisi informasi terperinci tentang tahun, bulan, hari, jam, menit, dan detik dalam zona waktu lokal user.

**Kode**:
<details>
<summary><h3>Klik untuk melihat detail</h3>></summary>

```c
// Get current timestamp
            time_t t = time(NULL);
            struct tm tm = *localtime(&t);
            char new_date[BUFFER_SIZE];
            snprintf(new_date, sizeof(new_date), "%02d/%02d/%04d %02d:%02d:%02d",
                     tm.tm_mday, tm.tm_mon + 1, tm.tm_year + 1900,
                     tm.tm_hour, tm.tm_min, tm.tm_sec);
```
</details>

