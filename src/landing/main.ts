import "./landing.css";

const year = document.querySelector<HTMLElement>("#copyright-year");

if (year) year.textContent = String(new Date().getFullYear());
