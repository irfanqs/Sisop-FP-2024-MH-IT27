# WIP!

# Sisop-FP-2024-MH-IT27
Anggota Kelompok :
|  NRP|Nama Anggota  |
|--|--|
|5027231079|Harwinda|
|5027221058|Irfan Qobus Salim|
|5027231038|Dani Wahyu Anak Ary|

# Pendahuluan
Dalam final project praktikum ini, kami diminta untuk menyelesaikan implementasi sebuah sistem chat yang terdiri dari tiga file utama yaitu discorit.c, server.c, dan monitor.c.

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

### CHAT

### Send Chat
Proses send chat dimulai dengan pengecekan apakah user berada dalam sebuah room. Jika user berada dalam room, sistem mempersiapkan path file chat.csv di dalam direktori room tersebut. Sistem kemudian membuka file chat.csv untuk menambahkan pesan baru. Jika file tidak bisa dibuka, sistem mengirim pesan kesalahan. Namun, jika file berhasil dibuka, sistem membaca file untuk mendapatkan ID terakhir dari pesan yang ada. Setelah itu, sistem mengambil timestamp saat ini dan menambahkan pesan baru dengan format timestamp, ID, username, message ke file chat.csv. Setelah pesan berhasil ditambahkan, file ditutup, dan sistem mengirim pesan sukses ke user yang berisi timestamp, ID, dan username dari pesan yang baru dikirim.

**Kode**:
<details>
<summary><h3>Klik untuk selengkapnya</h3>></summary>

```c
void send_chat(const char *username, const char *channel, const char *room, const char *message, int client_socket) {
    char chat_file[BUFFER_SIZE];
    snprintf(chat_file, sizeof(chat_file), "%s/%s/chat.csv", channel, room);
    FILE *file = fopen(chat_file, "a+");
    if (file == NULL) {
        perror("Failed to open chat file");
        send_response(client_socket, "Gagal mengirim pesan\n");
        return;
    }

    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    int id_chat = 1;

    if (file_size > 0) {
        fseek(file, 0, SEEK_SET);
        char line[BUFFER_SIZE];
        while (fgets(line, sizeof(line), file)) {
            id_chat++;
        }
    }

    time_t t = time(NULL);
    struct tm tm = *localtime(&t);
    char date[20];
    strftime(date, sizeof(date), "%d/%m/%Y %H:%M:%S", &tm);

    fprintf(file, "%s,%d,%s,\"%s\"\n", date, id_chat, username, message);
    fclose(file);

    send_response(client_socket, "Chat berhasil terkirim\n");
}
```
</details>

### See Chat
Sistem mempersiapkan path file chat.csv di dalam direktori room tersebut dan membuka file tersebut untuk membaca pesan-pesan yang ada. Jika file tidak bisa dibuka, sistem mengirim pesan kesalahan. Sistem membaca isi file chat satu per satu dan menggabungkan pesan-pesan tersebut ke dalam satu respons yang akan dikirim ke user.
**Kode**:
<details>
<summary><h3>Klik untuk selengkapnya</h3>></summary>

```c
void see_chat(const char *channel, const char *room, int client_socket) {
    char chat_file[BUFFER_SIZE];
    snprintf(chat_file, sizeof(chat_file), "%s/%s/chat.csv", channel, room);
    FILE *file = fopen(chat_file, "r");
    if (file == NULL) {
        perror("Failed to open chat file");
        send_response(client_socket, "Gagal melihat pesan\n");
        return;
    }

    char response[BUFFER_SIZE * 10] = "";
    char line[BUFFER_SIZE];
    char formatted_line[BUFFER_SIZE];

    while (fgets(line, sizeof(line), file)) {
        // Tokenize and reformat the line
        char *date = strtok(line, ",");
        char *id_chat = strtok(NULL, ",");
        char *sender = strtok(NULL, ",");
        char *chat = strtok(NULL, "\n");

        snprintf(formatted_line, sizeof(formatted_line), "[%s][%s][%s] %s\n", date, id_chat, sender, chat);
        strcat(response, formatted_line);
    }

    fclose(file);
    send_response(client_socket, response);

    // Debug statement to check if the room is correctly used
    printf("Debug: see_chat called for channel %s, room %s\n", channel, room);
    printf("Debug: chat_file path is %s\n", chat_file);
}
```
</details>

### Edit Chat
Dalam fungsi `edit_chat`, proses edit dilakukan dengan cara membaca setiap baris dari file `chat.csv` dan menyalinnya ke sebuah file sementara (`temp_file`) kecuali baris yang sesuai dengan ID yang ingin diubah. Proses ini memastikan bahwa hanya pesan yang sesuai dengan aturan perizinan yang diizinkan untuk diedit, sesuai dengan kebutuhan dan keamanan sistem. Setelah edit selesai, file sementara digunakan untuk mengganti file `chat.csv` asli, dan informasi edit dicatat dalam log sistem sebelum memberikan respons sukses kepada user.
**Kode**:
<details>
<summary><h3>Klik untuk selengkapnya</h3>></summary>

```c
void edit_chat(const char *channel, const char *room, int id_chat, const char *new_message, int client_socket) {
    char chat_file[BUFFER_SIZE];
    snprintf(chat_file, sizeof(chat_file), "%s/%s/chat.csv", channel, room);
    FILE *file = fopen(chat_file, "r");
    if (file == NULL) {
        perror("Failed to open chat file");
        send_response(client_socket, "Gagal mengedit pesan\n");
        return;
    }

    FILE *temp = fopen("temp.csv", "w");
    if (temp == NULL) {
        perror("Failed to open temporary file");
        fclose(file);
        send_response(client_socket, "Gagal mengedit pesan\n");
        return;
    }

    char line[BUFFER_SIZE];
    int found = 0;
    while (fgets(line, sizeof(line), file)) {
        char *date = strtok(line, ",");
        char *current_id_chat = strtok(NULL, ",");
        char *sender = strtok(NULL, ",");
        char *chat = strtok(NULL, "\n");

        if (atoi(current_id_chat) == id_chat) {
            found = 1;
            // Get current timestamp
            time_t t = time(NULL);
            struct tm tm = *localtime(&t);
            char new_date[BUFFER_SIZE];
            snprintf(new_date, sizeof(new_date), "%02d/%02d/%04d %02d:%02d:%02d",
                     tm.tm_mday, tm.tm_mon + 1, tm.tm_year + 1900,
                     tm.tm_hour, tm.tm_min, tm.tm_sec);

            fprintf(temp, "%s,%d,%s,\"%s\"\n", new_date, id_chat, sender, new_message);
        } else {
            fprintf(temp, "%s,%s,%s,%s\n", date, current_id_chat, sender, chat);
        }
    }

    fclose(file);
    fclose(temp);

    if (found) {
        remove(chat_file);
        rename("temp.csv", chat_file);
        send_response(client_socket, "Chat berhasil diedit\n");
    } else {
        remove("temp.csv");
        send_response(client_socket, "ID chat tidak ditemukan\n");
    }
}
```
</details>

### Delete Chat
Fungsi `del_chat` digunakan untuk menghapus chat dalam sebuah room chat berdasarkan ID tertentu. Pertama, fungsi memeriksa apakah user sedang berada di room chat tersebut. Jika tidak, fungsi akan memberitahu user bahwa mereka harus berada di room chat untuk melakukan penghapusan. Selanjutnya, fungsi membuka file tempat chat disimpan dan membuat file sementara untuk menyimpan hasil edit. Kemudian, fungsi membaca setiap chat dalam file chat. Ketika menemukan chat dengan ID yang sesuai dengan yang diminta untuk dihapus, fungsi memeriksa izin user: jika user adalah admin atau root, mereka dapat menghapus chat apa pun; jika hanya user biasa, mereka hanya bisa menghapus chat yang mereka tulis sendiri. Setelah menemukan chat yang sesuai untuk dihapus, chat tersebut tidak disalin ke file sementara, sehingga dihapus dari file asli. Jika ID yang diminta untuk dihapus tidak ditemukan, fungsi akan memberitahu user bahwa ID tersebut tidak ada dalam room chat. Setelah menghapus chat, file asli chat diperbarui dengan file sementara yang berisi perubahan, dan kegiatan penghapusan dicatat dalam log sistem. Akhirnya, user diberi tahu bahwa penghapusan berhasil dilakukan.
**Kode**:
<details>
<summary><h3>Klik untuk selengkapnya</h3>></summary>

```c
void delete_chat(const char *channel, const char *room, int id_chat, int client_socket) {
    char chat_file[BUFFER_SIZE];
    snprintf(chat_file, sizeof(chat_file), "%s/%s/chat.csv", channel, room);
    FILE *file = fopen(chat_file, "r");
    if (file == NULL) {
        perror("Failed to open chat file");
        send_response(client_socket, "Gagal menghapus pesan\n");
        return;
    }

    FILE *temp = fopen("temp.csv", "w");
    if (temp == NULL) {
        perror("Failed to open temporary file");
        fclose(file);
        send_response(client_socket, "Gagal menghapus pesan\n");
        return;
    }

    char line[BUFFER_SIZE];
    int found = 0;
    while (fgets(line, sizeof(line), file)) {
        char *date = strtok(line, ",");
        char *current_id_chat = strtok(NULL, ",");
        char *sender = strtok(NULL, ",");
        char *chat = strtok(NULL, "\n");

        if (atoi(current_id_chat) == id_chat) {
            found = 1;
            // Skip writing this line to delete it
            continue;
        } else {
            fprintf(temp, "%s,%s,%s,%s\n", date, current_id_chat, sender, chat);
        }
    }

    fclose(file);
    fclose(temp);

    if (found) {
        remove(chat_file);
        rename("temp.csv", chat_file);
        send_response(client_socket, "Chat berhasil dihapus\n");
    } else {
        remove("temp.csv");
        send_response(client_socket, "ID chat tidak ditemukan\n");
    }
}
```
</details>

**Hasil**
![image](https://github.com/Daniwahyuaa/readmefpsisop/assets/150106905/1fe7d296-bb1d-4749-b5d1-63dab5ee3e12)

## Admin 

### Create Channel
Fungsi create_channel bertujuan untuk membuat channel baru dalam sistem. fungsi akan membuka file channels.csv dan menambahkan entri baru untuk channel tersebut. fungsi ini membuat direktori baru untuk channel, direktori admin di dalamnya, dan file auth.csv di dalam direktori admin. Setelah semua direktori dan file yang diperlukan dibuat, fungsi ini mencatat kejadian pembuatan channel ke dalam log. Terakhir, fungsi ini mengirimkan pesan sukses ke client yang menunjukkan bahwa channel telah berhasil dibuat, dengan pemberi channel sebagai admin.
**Kode**:
<details>
<summary><h3>Klik untuk selengkapnya</h3>></summary>

```c
void create_channel(const char* username, const char* channel, const char* key, int client_socket) {
    FILE *file = fopen("channel.csv", "r+");
    if (file == NULL) {
        perror("Failed to open channel.csv");
        exit(EXIT_FAILURE);
    }

    char line[256];
    int id_channel = 0;
    while (fgets(line, sizeof(line), file)) {
        char *token = strtok(line, ",");
        int current_id = atoi(token);
        if (current_id > id_channel) {
            id_channel = current_id;
        }
    }

    id_channel++; // Increment the channel ID for the new channel
    fseek(file, 0, SEEK_END);
    char encrypted_key[BCRYPT_HASHSIZE];
    char salt[BCRYPT_HASHSIZE];

    if (bcrypt_gensalt(12, salt) != 0) {
        perror("Salt generation failed");
        fclose(file);
        return;
    }

    if (bcrypt_hashpw(key, salt, encrypted_key) != 0) {
        perror("Key encryption failed");
        fclose(file);
        return;
    }

    printf("Debug: created encrypted key %s\n", encrypted_key); // Debugging output

    fprintf(file, "%d,%s,%s\n", id_channel, channel, encrypted_key);
    fclose(file);

    // Create channel directory and admin directory
    char channel_dir[BUFFER_SIZE];
    snprintf(channel_dir, sizeof(channel_dir), "%s", channel);
    if (mkdir(channel_dir, 0755) != 0) {
        perror("Failed to create channel directory");
        send(client_socket, "Channel gagal dibuat\n", strlen("Channel gagal dibuat\n"), 0);
        return;
    }

    char admin_dir[BUFFER_SIZE];
    snprintf(admin_dir, sizeof(admin_dir), "%s/admin", channel);
    if (mkdir(admin_dir, 0755) != 0) {
        perror("Failed to create admin directory");
        send(client_socket, "Channel gagal dibuat\n", strlen("Channel gagal dibuat\n"), 0);
        return;
    }

    // Create auth.csv file inside admin directory
    char auth_file[BUFFER_SIZE];
    snprintf(auth_file, sizeof(auth_file), "%s/admin/auth.csv", channel);
    FILE *auth = fopen(auth_file, "w");
    if (auth == NULL) {
        perror("Failed to create auth.csv");
        return;
    }

    // Fetch the user ID and name
    int id_user = 1;

    // Fetch the user ID and name
    char user_name[50];
    FILE *users_file = fopen("users.csv", "r");
    if (users_file != NULL) {
        while (fgets(line, sizeof(line), users_file)) {
            char *token = strtok(line, ",");
            int user_id = atoi(token);
            token = strtok(NULL, ",");
            strcpy(user_name, token);
            if (strcmp(user_name, username) == 0) {
                id_user = user_id;
                break;
            }
        }
        fclose(users_file);
    }
    fprintf(auth, "%d,%s,ADMIN\n", id_user, user_name);
    fclose(auth);

    // Log the creation
    FILE *log = fopen("users.log", "a");
    if (log != NULL) {
        time_t t = time(NULL);
        struct tm tm = *localtime(&t);
        fprintf(log, "[%02d/%02d/%04d %02d:%02d:%02d] %s membuat %s\n",
                tm.tm_mday, tm.tm_mon + 1, tm.tm_year + 1900,
                tm.tm_hour, tm.tm_min, tm.tm_sec,
                username, channel);
        fclose(log);
    }

    send(client_socket, "Channel berhasil dibuat\n", strlen("Channel berhasil dibuat\n"), 0);
}
```
</details>

### Edit Channel
Fungsi edit_channel bertujuan untuk mengubah nama channel yang sudah ada. Proses ini dimulai dengan memeriksa izin pengguna untuk channel yang akan diubah menggunakan fungsi check_channel_perms. Jika izin pengguna tidak mencukupi, fungsi akan mengirim pesan error ke client. Jika izin mencukupi, fungsi akan membuka file channels.csv dan file sementara untuk menyimpan data yang telah dimodifikasi. Selanjutnya, fungsi akan membaca setiap entri di channels.csv dan membandingkannya dengan nama channel yang akan diubah. Jika ditemukan kecocokan, fungsi akan menulis entri baru dengan nama channel yang baru ke file sementara. Jika tidak ada kecocokan, entri lama akan ditulis ulang ke file sementara. Setelah semua entri diproses, file asli channels.csv akan dihapus dan file sementara akan diganti namanya menjadi channels.csv. Jika channel yang diubah adalah channel yang sedang digunakan oleh client. Terakhir, fungsi akan mengirim pesan sukses ke client yang menunjukkan bahwa nama channel telah berhasil diubah.
**Kode**:
<details>
<summary><h3>Klik untuk selengkapnya</h3>></summary>

```c
void edit_channel(const char* username, const char* old_channel, const char* new_channel, int client_socket) {
    FILE *file = fopen("channel.csv", "r");
    if (file == NULL) {
        perror("Failed to open channel.csv");
        exit(EXIT_FAILURE);
    }

    FILE *temp = fopen("temp.csv", "w");
    if (temp == NULL) {
        perror("Failed to open temp.csv");
        fclose(file);
        exit(EXIT_FAILURE);
    }

    char line[256];
    int found = 0;
    while (fgets(line, sizeof(line), file)) {
        char *token = strtok(line, ",");
        int id_channel = atoi(token);
        char *channel_name = strtok(NULL, ",");
        char *key = strtok(NULL, ",");

        if (strcmp(channel_name, old_channel) == 0) {
            fprintf(temp, "%d,%s,%s", id_channel, new_channel, key);
            found = 1;
        } else {
            fprintf(temp, "%d,%s,%s", id_channel, channel_name, key);
        }
    }

    fclose(file);
    fclose(temp);

    if (found) {
        remove("channel.csv");
        rename("temp.csv", "channel.csv");

        // Rename the channel directory using POSIX function
        if (rename(old_channel, new_channel) != 0) {
            perror("Failed to rename channel directory");
            send(client_socket, "Channel gagal diubah\n", strlen("Channel gagal diubah\n"), 0);
            return;
        }

        // Log the rename
        FILE *log = fopen("users.log", "a");
        if (log != NULL) {
            time_t t = time(NULL);
            struct tm tm = *localtime(&t);
            fprintf(log, "[%02d/%02d/%04d %02d:%02d:%02d] %s mengubah %s menjadi %s\n",
                    tm.tm_mday, tm.tm_mon + 1, tm.tm_year + 1900,
                    tm.tm_hour, tm.tm_min, tm.tm_sec,
                    username, old_channel, new_channel);
            fclose(log);
        }

        send(client_socket, "Channel berhasil diubah\n", strlen("Channel berhasil diubah\n"), 0);
    } else {
        remove("temp.csv");
        send(client_socket, "Channel tidak ditemukan\n", strlen("Channel tidak ditemukan\n"), 0);
    }
}
```
</details>

### Delete Channel

Del Channel
Fungsi delete_channel digunakan untuk menghapus channel yang ada. fungsi akan membuka file channels.csv dan file sementara untuk menyimpan data yang telah dimodifikasi. Selanjutnya, fungsi akan membaca setiap entri di channels.csv dan membandingkannya dengan nama channel yang akan dihapus. Jika tidak ditemukan kecocokan, entri lama akan ditulis ulang ke file sementara. Jika ditemukan kecocokan, entri tersebut tidak akan ditulis ulang, menandakan bahwa channel tersebut telah dihapus. Setelah semua entri diproses, file asli channels.csv akan dihapus dan file sementara akan diganti namanya menjadi channels.csv. Kemudian, fungsi akan menghapus direktori channel yang dihapus dengan memanggil remove_directory. Jika channel yang dihapus adalah channel yang sedang digunakan oleh client, fungsi juga akan memperbarui data client untuk mengosongkan nama channel dan room yang sedang digunakan, serta mengirim pesan keluar ke client. Terakhir, fungsi akan mengirim pesan sukses ke client yang menunjukkan bahwa channel telah berhasil dihapus.
**Kode**

<details>
<summary><h3>Klik untuk selengkapnya</h3>></summary>

```c
void delete_channel(const char* username, const char* channel, int client_socket) {
    FILE *file = fopen("channel.csv", "r");
    if (file == NULL) {
        perror("Failed to open channel.csv");
        exit(EXIT_FAILURE);
    }

    FILE *temp = fopen("temp.csv", "w");
    if (temp == NULL) {
        perror("Failed to open temp.csv");
        fclose(file);
        exit(EXIT_FAILURE);
    }

    char line[256];
    int found = 0;
    while (fgets(line, sizeof(line), file)) {
        char *token = strtok(line, ",");
        int id_channel = atoi(token);
        char *channel_name = strtok(NULL, ",");
        char *key = strtok(NULL, ",");

        if (strcmp(channel_name, channel) == 0) {
            found = 1;
        } else {
            fprintf(temp, "%d,%s,%s", id_channel, channel_name, key);
        }
    }

    fclose(file);
    fclose(temp);

    if (found) {
        remove("channel.csv");
        rename("temp.csv", "channel.csv");

        // Remove the channel directory using POSIX function
        delete_directory(channel);

        // Log the deletion
        FILE *log = fopen("users.log", "a");
        if (log != NULL) {
            time_t t = time(NULL);
            struct tm tm = *localtime(&t);
            fprintf(log, "[%02d/%02d/%04d %02d:%02d:%02d] %s menghapus %s\n",
                    tm.tm_mday, tm.tm_mon + 1, tm.tm_year + 1900,
                    tm.tm_hour, tm.tm_min, tm.tm_sec,
                    username, channel);
            fclose(log);
        }

        send(client_socket, "Channel berhasil dihapus\n", strlen("Channel berhasil dihapus\n"), 0);
    } else {
        remove("temp.csv");
        send(client_socket, "Channel tidak ditemukan\n", strlen("Channel tidak ditemukan\n"), 0);
    }
}

```
</details>

**Hasil**
![image](https://github.com/Daniwahyuaa/readmefpsisop/assets/150106905/486123c9-0e1a-4b80-80b8-489a8b011d2c)

### Delete Room All
**Penjelasan**: Fungsi `delete_all_rooms` digunakan untuk menghapus semua room yang ada dalam sebuah channel. Fungsi ini juga memastikan bahwa user memiliki izin yang cukup untuk melakukan tindakan ini dan memperbarui status user jika mereka berada di dalam salah satu room yang dihapus.

**Alur**:
1. **Inisialisasi Buffer**: 
   ```c
   char buffer[1024];
   ```
   - Sebuah array karakter dengan nama `buffer` dan ukuran 1024 byte dideklarasikan. Buffer ini digunakan untuk menyimpan perintah yang akan dikirim ke server dan juga untuk menyimpan respons yang diterima dari server.

2. **Konstruksi Perintah**: 
   ```c
   sprintf(buffer, "DEL ROOM ALL");
   ```
   - Fungsi `sprintf` digunakan untuk memformat string `"DEL ROOM ALL"` dan menyimpannya dalam buffer. String ini merupakan perintah yang akan dikirim ke server untuk menghapus semua ruangan.

3. **Mengirim Perintah ke Socket**: 
   ```c
   send(sock, buffer, strlen(buffer), 0);
   ```
   - Fungsi `send` digunakan untuk mengirimkan isi dari buffer melalui socket yang telah ditentukan sebelumnya (`sock`). `strlen(buffer)` digunakan untuk menentukan panjang data yang akan dikirim (dalam hal ini, panjang string `"DEL ROOM ALL"`).

4. **Membersihkan Buffer**: 
   ```c
   memset(buffer, 0, sizeof(buffer));
   ```
   - Fungsi `memset` digunakan untuk mengatur ulang buffer menjadi nol (`0`). Hal ini dilakukan untuk menghapus data sebelumnya yang mungkin masih ada di dalam buffer sebelum membaca respons dari server.

5. **Membaca Respons dari Socket**: 
   ```c
   read(sock, buffer, sizeof(buffer));
   ```
   - Fungsi `read` digunakan untuk membaca respons dari server dan menyimpannya kembali ke dalam buffer. `sizeof(buffer)` digunakan untuk memastikan bahwa buffer memiliki ukuran yang cukup untuk menampung respons yang diterima dari server.

6. **Mencetak Respons**: 
   ```c
   printf("%s\n", buffer);
   ```
   - Fungsi `printf` digunakan untuk mencetak isi dari buffer, yang sekarang berisi respons yang diterima dari server. Respons ini kemungkinan berisi pesan konfirmasi atau status yang menegaskan bahwa operasi penghapusan ruangan telah berhasil dilakukan.

### Catatan Tambahan:
- Pastikan bahwa socket (`sock`) telah diinisialisasi dan terhubung dengan server sebelum memanggil fungsi `delete_all_rooms`.
- Penanganan kesalahan (error handling) untuk operasi-operasi socket seperti `send` dan `read` perlu diimplementasikan untuk mengatasi kemungkinan kegagalan operasi jaringan.
- Bergantung pada aplikasi dan implementasi server Anda, mungkin diperlukan penanganan kesalahan tambahan atau mekanisme untuk memastikan keandalan operasi ini.

**Kode**:
<details>
<summary><h3>Klik untuk selengkapnya</h3>></summary>
   
   ```c

    void delete_all_rooms(int sock) {
    char buffer[1024];
    sprintf(buffer, "DEL ROOM ALL");
    send(sock, buffer, strlen(buffer), 0);
    memset(buffer, 0, sizeof(buffer));
    read(sock, buffer, sizeof(buffer));
    printf("%s\n", buffer);
}
```
</details>

### Ban
#### Ban User
**Penjelasan**:
Fungsi `check_ban` bertujuan untuk memeriksa apakah user yang terhubung ke server saat ini telah dibanned dari channel yang mereka coba akses. Fungsi ini mengakses file `auth.csv` di folder `admin` pada channel untuk memeriksa status user.

### Penjelasan Alur Kode:

1. **Validasi Izin Akses**:
   - Fungsi `validate_csv_users` dan `validate_csv_auth_admin` dipanggil untuk memeriksa izin admin terhadap pengguna dan otorisasi pada kanal tertentu. Jika tidak valid, respons "Permission denied" dikirimkan ke client dan fungsi diakhiri.

2. **Membuka File Auth.csv**:
   - File `auth.csv` dari direktori yang sesuai dengan kanal dibuka dengan mode `r+` untuk operasi read/write.

3. **Membuka File Temp.csv**:
   - File `temp.csv` juga dibuka sebagai file sementara dengan mode `w` untuk penulisan.

4. **Memproses Baris Auth.csv**:
   - Setiap baris dari `auth.csv` dibaca dan diproses. Data di baris ini dipisahkan menggunakan `strtok` untuk mendapatkan `id_user`, `username`, dan `role`.

5. **Penanganan User yang Akan Diban**:
   - Jika `username` sesuai dengan `user_to_ban`, baris baru dengan status `BANNED` ditulis ke `temp.csv`. Variabel `found` disetel ke 1 untuk menunjukkan bahwa user telah ditemukan.
   - Jika tidak sesuai, baris yang ada disalin ke `temp.csv` tanpa perubahan.

6. **Penyelesaian Operasi**:
   - Setelah semua baris diproses, file `auth.csv` dan `temp.csv` ditutup.
   - Jika user berhasil diban (`found` adalah 1):
     - `auth.csv` lama dihapus dan `temp.csv` diubah namanya menjadi `auth.csv`.
     - Tindakan ban dicatat di `users.log`.
     - Respons "User berhasil diban" dikirimkan ke client.
   - Jika user tidak ditemukan (`found` tetap 0):
     - `temp.csv` dihapus.
     - Respons "User tidak ditemukan" dikirimkan ke client.
     
**Kode**:
<details>
<summary><h3>Klik untuk selengkapnya</h3>></summary>

   ```c
void ban_user(const char *admin, const char *channel, const char *user_to_ban, int client_socket) {
    if (!(validate_csv_users(admin, client_socket) || validate_csv_auth_admin(admin, channel))) {
        send_response(client_socket, "Permission denied\n");
        return;
    }

    char auth_file[BUFFER_SIZE];
    snprintf(auth_file, sizeof(auth_file), "%s/admin/auth.csv", channel);
    FILE *file = fopen(auth_file, "r+");
    if (file == NULL) {
        perror("Failed to open auth.csv");
        send_response(client_socket, "Gagal membuka auth.csv\n");
        return;
    }

    char temp_file[BUFFER_SIZE];
    snprintf(temp_file, sizeof(temp_file), "%s/admin/temp.csv", channel);
    FILE *temp = fopen(temp_file, "w");
    if (temp == NULL) {
        perror("Failed to open temp.csv");
        fclose(file);
        send_response(client_socket, "Gagal membuka temp.csv\n");
        return;
    }

    char line[BUFFER_SIZE];
    int found = 0;
    while (fgets(line, sizeof(line), file)) {
        char *id_user = strtok(line, ",");
        char *username = strtok(NULL, ",");
        char *role = strtok(NULL, "\n");

        if (strcmp(username, user_to_ban) == 0) {
            fprintf(temp, "%s,%s,BANNED\n", id_user, username);
            found = 1;
        } else {
            fprintf(temp, "%s,%s,%s\n", id_user, username, role);
        }
    }

    fclose(file);
    fclose(temp);

    if (found) {
        remove(auth_file);
        rename(temp_file, auth_file);

        // Log the ban
        char log_path[BUFFER_SIZE];
        snprintf(log_path, sizeof(log_path), "%s/admin/users.log", channel);
        FILE *log = fopen(log_path, "a");
        if (log != NULL) {
            time_t t = time(NULL);
            struct tm tm = *localtime(&t);
            fprintf(log, "[%02d/%02d/%04d %02d:%02d:%02d] %s memban %s\n",
                    tm.tm_mday, tm.tm_mon + 1, tm.tm_year + 1900,
                    tm.tm_hour, tm.tm_min, tm.tm_sec,
                    admin, user_to_ban);
            fclose(log);
        }

        send_response(client_socket, "User berhasil diban\n");
    } else {
        remove(temp_file);
        send_response(client_socket, "User tidak ditemukan\n");
    }
}


```
</details>

**Hasil**
![image](https://github.com/Daniwahyuaa/readmefpsisop/assets/150106905/dd4b818c-fc35-4597-9b00-606fe7ce1249)

## Unban User
#### Penjelasan:
Fungsi `unban_user` digunakan untuk menghapus status banned dari user tertentu di sebuah channel. Fungsi ini mengecek apakah user yang ingin di-unbanned ada dalam channel dan memiliki status "BANNED". Jika user valid ditemukan, maka statusnya diubah kembali ke status semula sebelum di-banned.

### Penjelasan Alur Kode:

1. **Validasi Izin Akses**:
   - Fungsi `validate_csv_users` dan `validate_csv_auth_admin` dipanggil untuk memverifikasi izin admin terhadap pengguna dan otorisasi pada kanal tertentu. Jika tidak valid, pesan "Permission denied" dikirimkan ke client dan fungsi berhenti.

2. **Membuka File Auth.csv**:
   - File `auth.csv` dari direktori yang sesuai dengan kanal dibuka dengan mode `r+` untuk operasi read/write.

3. **Membuka File Temp.csv**:
   - File `temp.csv` juga dibuka sebagai file sementara dengan mode `w` untuk penulisan.

4. **Memproses Baris Auth.csv**:
   - Setiap baris dari `auth.csv` dibaca dan diproses. Data di baris ini dipisahkan menggunakan `strtok` untuk mendapatkan `id_user`, `username`, dan `role`.

5. **Penanganan User yang Akan Diunban**:
   - Jika `username` sesuai dengan `user_to_unban`, baris baru dengan status `USER` (tidak diblokir) ditulis ke `temp.csv`. Variabel `found` disetel ke 1 untuk menunjukkan bahwa user telah ditemukan dan diunban.
   - Jika tidak sesuai, baris yang ada disalin ke `temp.csv` tanpa perubahan.

6. **Penyelesaian Operasi**:
   - Setelah semua baris diproses, file `auth.csv` dan `temp.csv` ditutup.
   - Jika user berhasil diunban (`found` adalah 1):
     - `auth.csv` lama dihapus dan `temp.csv` diubah namanya menjadi `auth.csv`.
     - Tindakan unban dicatat di `users.log`.
     - Respons "User berhasil diunban" dikirimkan ke client.
   - Jika user tidak ditemukan (`found` tetap 0):
     - `temp.csv` dihapus.
     - Respons "User tidak ditemukan" dikirimkan ke client.

**Kode**:
<details>
<summary><h3>Klik untuk selengkapnya</h3>></summary>

   ```c
void unban_user(const char *admin, const char *channel, const char *user_to_unban, int client_socket) {
    if (!(validate_csv_users(admin, client_socket) || validate_csv_auth_admin(admin, channel))) {
        send_response(client_socket, "Permission denied\n");
        return;
    }

    char auth_file[BUFFER_SIZE];
    snprintf(auth_file, sizeof(auth_file), "%s/admin/auth.csv", channel);
    FILE *file = fopen(auth_file, "r+");
    if (file == NULL) {
        perror("Failed to open auth.csv");
        send_response(client_socket, "Gagal membuka auth.csv\n");
        return;
    }

    char temp_file[BUFFER_SIZE];
    snprintf(temp_file, sizeof(temp_file), "%s/admin/temp.csv", channel);
    FILE *temp = fopen(temp_file, "w");
    if (temp == NULL) {
        perror("Failed to open temp.csv");
        fclose(file);
        send_response(client_socket, "Gagal membuka temp.csv\n");
        return;
    }

    char line[BUFFER_SIZE];
    int found = 0;
    while (fgets(line, sizeof(line), file)) {
        char *id_user = strtok(line, ",");
        char *username = strtok(NULL, ",");
        char *role = strtok(NULL, "\n");

        if (strcmp(username, user_to_unban) == 0) {
            fprintf(temp, "%s,%s,USER\n", id_user, username);
            found = 1;
        } else {
            fprintf(temp, "%s,%s,%s\n", id_user, username, role);
        }
    }

    fclose(file);
    fclose(temp);

    if (found) {
        remove(auth_file);
        rename(temp_file, auth_file);

        // Log the unban
        char log_path[BUFFER_SIZE];
        snprintf(log_path, sizeof(log_path), "%s/admin/users.log", channel);
        FILE *log = fopen(log_path, "a");
        if (log != NULL) {
            time_t t = time(NULL);
            struct tm tm = *localtime(&t);
            fprintf(log, "[%02d/%02d/%04d %02d:%02d:%02d] %s mengunban %s\n",
                    tm.tm_mday, tm.tm_mon + 1, tm.tm_year + 1900,
                    tm.tm_hour, tm.tm_min, tm.tm_sec,
                    admin, user_to_unban);
            fclose(log);
        }

        send_response(client_socket, "User berhasil diunban\n");
    } else {
        remove(temp_file);
        send_response(client_socket, "User tidak ditemukan\n");
    }
}
```
</details>

**Hasil**
![image](https://github.com/Daniwahyuaa/readmefpsisop/assets/150106905/9de777e1-e903-420c-9fa2-87ce69300a76)

### User
#### List User In Channer
**Penjelasan**: Fungsi `list_user` digunakan untuk menampilkan daftar semua pengguna yang ada di dalam channel. Hanya pengguna dengan peran "ROOT" yang diizinkan untuk menggunakan fungsi ini.

### Penjelasan Alur Kode:

1. **Membuka File Auth.csv**:
   - File `auth.csv` dari direktori yang sesuai dengan kanal dibuka dengan mode `r` untuk operasi read-only.

2. **Inisialisasi Variabel**:
   - Variabel `line` digunakan untuk menyimpan setiap baris yang dibaca dari file.
   - Variabel `response` digunakan sebagai buffer untuk menyimpan daftar pengguna yang akan dikirimkan ke client.

3. **Membaca dan Mengolah Baris**:
   - Selama ada baris yang dapat dibaca dari `auth.csv`, fungsi `fgets` digunakan untuk membacanya.
   - Setiap baris dipisahkan menjadi `id_user` dan `username` menggunakan `strtok`.
   - Username dari setiap baris ditambahkan ke variabel `response` dengan menambahkan spasi setelahnya.

4. **Penyelesaian Operasi**:
   - Setelah semua baris diproses, file `auth.csv` ditutup.
   - Jika tidak ada username yang ditambahkan ke `response` (panjang string `response` adalah 0), kirimkan pesan "Tidak ada user di channel ini" ke client.
   - Jika ada username yang ditambahkan ke `response`, kirimkan `response` (daftar pengguna) ke client.

**Kode**:
<details>
<summary><h3>Klik untuk melihat detail</h3>></summary>

```c
void list_users_in_channel(const char *channel, int client_socket) {
    char auth_file[BUFFER_SIZE];
    snprintf(auth_file, sizeof(auth_file), "%s/admin/auth.csv", channel);
    FILE *file = fopen(auth_file, "r");
    if (file == NULL) {
        perror("Failed to open auth.csv");
        send_response(client_socket, "Gagal membuka auth.csv\n");
        return;
    }

    char line[BUFFER_SIZE];
    char response[BUFFER_SIZE] = "";

    while (fgets(line, sizeof(line), file)) {
        char *id_user = strtok(line, ",");
        char *username = strtok(NULL, ",");
        strcat(response, username);
        strcat(response, " ");
    }

    fclose(file);

    // If no users found, send appropriate response
    if (strlen(response) == 0) {
        send_response(client_socket, "Tidak ada user di channel ini\n");
    } else {
        send_response(client_socket, response);
    }
}
```
</details>
