document.addEventListener("DOMContentLoaded", function () {
  const authForm = document.getElementById("authForm");
  const signupBtn = document.getElementById("signupBtn");
  const loginBtn = document.getElementById("loginBtn");

  signupBtn.addEventListener("click", function () {
    const name = document.getElementById("name").value.trim();
    const email = document.getElementById("email").value.trim();
    const password = document.getElementById("password").value;

    if (!name || !email || !password) {
      alert("All fields are required for sign-up.");
      return;
    }

    fetch("signup.php", {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded"
      },
      body: `name=${encodeURIComponent(name)}&email=${encodeURIComponent(email)}&password=${encodeURIComponent(password)}`
    })
    .then(res => res.text())
    .then(data => {
      alert(data);
      if (data.toLowerCase().includes("success")) {
        window.location.href = "landing_page.html";
      }
    })
    .catch(err => {
      console.error("Signup error:", err);
      alert("An error occurred during sign-up.");
    });
  });

  authForm.addEventListener("submit", function (e) {
    e.preventDefault();

    const email = document.getElementById("email").value.trim();
    const password = document.getElementById("password").value;

    if (!email || !password) {
      alert("Email and password are required.");
      return;
    }

    fetch("login.php", {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded"
      },
      body: `email=${encodeURIComponent(email)}&password=${encodeURIComponent(password)}`
    })
    .then(res => res.text())
    .then(data => {
      alert(data);
      if (data.toLowerCase().includes("success")) {
        window.location.href = "landing_page.html";
      }
    })
    .catch(err => {
      console.error("Login error:", err);
      alert("An error occurred during login.");
    });
  });
});
