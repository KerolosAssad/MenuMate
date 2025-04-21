// Automatically switches between local and tunnel depending on domain
const API_BASE_URL = location.hostname.includes("localhost")
  ? "http://localhost:5000"
  : "https://modern-sides-see.loca.lt";
