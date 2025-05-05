let currentUser = null;

async function checkUserSession() {
  try {
    const res = await fetch(`${API_BASE_URL}/api/user`, {
      credentials: "include",
    });
    const data = await res.json();

    if (data.logged_in) {
      currentUser = data.email;
      setupLogout();
      startExperiencePass();
    } else {
      alert("You must be logged in to access this page.");
      redirectToLogin();
    }
  } catch (err) {
    console.error("Login check failed:", err);
    alert("⚠️ Login session error.");
    redirectToLogin();
  }
}

function redirectToLogin() {
  window.location.href = "https://kerolosassad.github.io/MenuMate/index.html";
}

function setupLogout() {
  const loginBtn = document.querySelector(".header-btn");
  if (loginBtn) {
    loginBtn.textContent = "Log Out";
    loginBtn.addEventListener("click", () => {
      // Trigger logout via full-page redirect (ensures session.clear() executes)
      window.location.href = `${API_BASE_URL}/logout`;
    });
  }
}

async function startExperiencePass() {
  async function sendLocation() {
    if (!navigator.geolocation) return;

    navigator.geolocation.getCurrentPosition(async (position) => {
      const { latitude, longitude } = position.coords;

      try {
        await fetch(`${API_BASE_URL}/api/track_location`, {
          method: "POST",
          credentials: "include",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({ latitude, longitude }),
        });

        await fetchAndShareExperience();
      } catch (err) {
        console.warn("Location send failed:", err);
      }
    });
  }

  async function fetchAndShareExperience() {
    try {
      const res = await fetch(`${API_BASE_URL}/api/experience/get`, {
        credentials: "include",
      });
      const data = await res.json();

      if (data && data.name) {
        await fetch(`${API_BASE_URL}/api/experience/share`, {
          method: "POST",
          credentials: "include",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify(data),
        });
      }
    } catch (err) {
      console.warn("Experience share failed:", err);
    }
  }

  await sendLocation();
  setInterval(sendLocation, 30000); // Keep checking location
}

// Initialize session check on page load
checkUserSession();
