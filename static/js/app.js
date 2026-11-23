document.addEventListener("DOMContentLoaded", () => {
  document.querySelectorAll("form[onsubmit]").forEach(form => {
    form.addEventListener("submit", () => {
      const button = form.querySelector("button[type=submit]");
      if (button) { button.disabled = true; }
    });
  });
});
