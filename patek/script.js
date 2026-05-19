// Year
document.getElementById("year").textContent = new Date().getFullYear();

// Header shrink on scroll
const header = document.getElementById("header");
const onScroll = () => {
  header.classList.toggle("is-shrunk", window.scrollY > 40);
};
window.addEventListener("scroll", onScroll, { passive: true });
onScroll();

// Mobile nav
const burger = document.getElementById("burger");
const nav = document.getElementById("nav");
burger.addEventListener("click", () => {
  const open = nav.classList.toggle("is-open");
  burger.classList.toggle("is-open", open);
  document.body.style.overflow = open ? "hidden" : "";
});
nav.querySelectorAll("a").forEach((a) =>
  a.addEventListener("click", () => {
    nav.classList.remove("is-open");
    burger.classList.remove("is-open");
    document.body.style.overflow = "";
  })
);

// Reveal on scroll
const revealEls = document.querySelectorAll("[data-reveal]");
const revealObserver = new IntersectionObserver(
  (entries) => {
    entries.forEach((entry) => {
      if (entry.isIntersecting) {
        entry.target.classList.add("is-visible");
        revealObserver.unobserve(entry.target);
      }
    });
  },
  { threshold: 0.15 }
);
revealEls.forEach((el) => revealObserver.observe(el));

// Animated counters
const counters = document.querySelectorAll(".stat__num");
const countObserver = new IntersectionObserver(
  (entries) => {
    entries.forEach((entry) => {
      if (!entry.isIntersecting) return;
      const el = entry.target;
      const target = parseInt(el.dataset.count, 10);
      const duration = 1600;
      const start = performance.now();
      const tick = (now) => {
        const p = Math.min((now - start) / duration, 1);
        const eased = 1 - Math.pow(1 - p, 3);
        el.textContent = Math.round(eased * target);
        if (p < 1) requestAnimationFrame(tick);
      };
      requestAnimationFrame(tick);
      countObserver.unobserve(el);
    });
  },
  { threshold: 0.5 }
);
counters.forEach((c) => countObserver.observe(c));

// Newsletter
const form = document.getElementById("newsletterForm");
const msg = document.getElementById("newsletterMsg");
form.addEventListener("submit", (e) => {
  e.preventDefault();
  const email = form.email.value.trim();
  const valid = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
  if (!valid) {
    msg.textContent = "Bitte geben Sie eine gültige E-Mail-Adresse ein.";
    msg.style.color = "#d9a679";
    return;
  }
  msg.textContent = "Vielen Dank — Ihre Anmeldung wurde bestätigt.";
  msg.style.color = "var(--gold)";
  form.reset();
});
