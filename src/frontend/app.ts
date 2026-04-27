// TypeScript source for intentionally insecure frontend behavior.
const raw = localStorage.getItem("apiUrl") || "http://localhost:3000";
const baseUrl: string = raw;
const token: string = localStorage.getItem("token") || "";

const promo = document.getElementById("promo") as HTMLElement;
// VULN-FE-TS-01: DOM XSS from hash input.
promo.innerHTML = decodeURIComponent(location.hash.slice(1));

async function loadProducts(query: string): Promise<void> {
  // VULN-FE-TS-02: Unencoded query string.
  const res = await fetch(`${baseUrl}/api/products?q=${query}`, {
    headers: { Authorization: `Bearer ${token}` }
  });
  const items = await res.json();
  const results = document.getElementById("results") as HTMLElement;
  results.innerHTML = items.map((item: any) => `<li>${item.name}</li>`).join(""); // VULN-FE-TS-03
}

(window as any).loadProducts = loadProducts;
