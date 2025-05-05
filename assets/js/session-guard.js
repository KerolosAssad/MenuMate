let currentUser = null;

async function checkUserSession() {
  try {
    const res = await fetch(`${API_BASE_URL}/api/user`, { credentials: "include" });
    const data = await res.json();

    if (data.logged_in) {
      currentUser = data.email;
      setupLogout();
      startExperiencePass();
    } else {
      alert("You must be logged in to access this page.");
      window.location.href = "https://kerolosassad.github.io/MenuMate/";
    }
  } catch (err) {
    console.error("Login check failed", err);
    alert("Login session error.");
    window.location.href = "https://kerolosassad.github.io/MenuMate/";
  }
}

function setupLogout() {
  const loginBtn = document.querySelector(".header-btn");
  if (loginBtn) {
    loginBtn.textContent = "Log Out";
    loginBtn.addEventListener("click", async () => {
      await fetch(`${API_BASE_URL}/api/logout`, { credentials: "include" });
      window.location.href = "https://kerolosassad.github.io/MenuMate/";
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
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ latitude, longitude })
        });
        await fetchAndShareExperience();
      } catch (err) {
        console.warn("Location send failed.", err);
      }
    });
  }

  async function fetchAndShareExperience() {
    try {
      const res = await fetch(`${API_BASE_URL}/api/experience/get`, { credentials: "include" });
      const data = await res.json();
      if (data && data.name) {
        await fetch(`${API_BASE_URL}/api/experience/share`, {
          method: "POST",
          credentials: "include",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(data)
        });
      }
    } catch (err) {
      console.warn("Experience share failed.", err);
    }
  }

  await sendLocation();
  setInterval(sendLocation, 30000);
}

checkUserSession();
