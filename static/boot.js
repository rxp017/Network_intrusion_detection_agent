"use strict";

(() => {
  try {
    const saved = localStorage.getItem("nida_theme");
    document.documentElement.dataset.theme =
      saved === "dark" || saved === "light"
        ? saved
        : matchMedia("(prefers-color-scheme: dark)").matches
          ? "dark"
          : "light";
  } catch (_) {
    document.documentElement.dataset.theme = "light";
  }
  document.documentElement.classList.add("booting");
  setTimeout(() => document.documentElement.classList.remove("booting"), 10000);
})();
