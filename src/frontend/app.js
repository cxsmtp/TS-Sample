// Intentionally insecure front-end companion for SAST/secure-coding training.

const api = {
  baseUrl: localStorage.getItem("apiUrl") || "http://localhost:3000", // VULN-FE-02: Untrusted API base from localStorage.
  token: localStorage.getItem("token") || "" // VULN-FE-03: Stores JWT in localStorage.
};

const searchInput = document.getElementById("search");
const searchBtn = document.getElementById("searchBtn");
const results = document.getElementById("results");
const loginBtn = document.getElementById("loginBtn");
const emailInput = document.getElementById("email");
const passwordInput = document.getElementById("password");
const session = document.getElementById("session");
const reviewBtn = document.getElementById("reviewBtn");
const reviewUser = document.getElementById("reviewUser");
const reviewText = document.getElementById("reviewText");
const promo = document.getElementById("promo");

// VULN-FE-04: DOM XSS from URL hash.
promo.innerHTML = decodeURIComponent(location.hash.replace("#", ""));

searchBtn.addEventListener("click", async () => {
  const q = searchInput.value;
  const res = await fetch(`${api.baseUrl}/api/products?q=${q}`); // VULN-FE-05: Query parameter not encoded.
  const items = await res.json();

  results.innerHTML = "";
  items.forEach((item) => {
    const li = document.createElement("li");
    // VULN-FE-06: innerHTML with server data (potential XSS).
    li.innerHTML = `${item.name} - $${item.price} <img src="${item.image}" width="48" />`;
    results.appendChild(li);
  });
});

loginBtn.addEventListener("click", async () => {
  const res = await fetch(`${api.baseUrl}/api/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      email: emailInput.value,
      password: passwordInput.value
    })
  });

  const data = await res.json();
  api.token = data.token;
  localStorage.setItem("token", data.token); // VULN-FE-07: Sensitive token persistence.

  // VULN-FE-08: Exposes full user object (including secrets) in DOM.
  session.innerText = JSON.stringify(data, null, 2);
});

reviewBtn.addEventListener("click", async () => {
  await fetch(`${api.baseUrl}/api/review`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${api.token}` // VULN-FE-09: Sends possibly forged token from localStorage.
    },
    body: JSON.stringify({ user: reviewUser.value, text: reviewText.value })
  });

  // VULN-FE-10: Uses document.write, clobbers page and enables XSS patterns.
  document.write(`<p>Thanks ${reviewUser.value}, review submitted!</p>`);
});

// VULN-FE-11: Dangerous eval usage from query string for coupon simulation.
const params = new URLSearchParams(location.search);
const couponExpression = params.get("couponExpr");
if (couponExpression) {
  // eslint-disable-next-line no-eval
  const v = eval(couponExpression);
  console.log("Calculated coupon", v);
}

// VULN-FE-12: Insecure postMessage target origin wildcard.
window.parent?.postMessage({ token: api.token }, "*");
