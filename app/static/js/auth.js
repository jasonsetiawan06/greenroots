function showRegister() {
    document.getElementById("login-form").hidden = true;
    document.getElementById("register-form").hidden = false;

    document.getElementById("form-title").textContent = "Buat Akun Baru";
    document.getElementById("form-description").textContent =
        "Isi data berikut untuk bergabung dengan GreenRoots.";
}

function showLogin() {
    document.getElementById("register-form").hidden = true;
    document.getElementById("login-form").hidden = false;

    document.getElementById("form-title").textContent =
        "Selamat Datang Kembali";
    document.getElementById("form-description").textContent =
        "Masuk ke akunmu untuk melanjutkan kontribusi penghijauan.";
}