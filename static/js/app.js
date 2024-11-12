document.addEventListener("DOMContentLoaded", function () {
  const termsCheckbox = document.getElementById("accept-terms");
  const actionButton = document.getElementById("submitButton");

  termsCheckbox.addEventListener("change", function () {
    actionButton.disabled = !termsCheckbox.checked;

    if (termsCheckbox.checked) {
      actionButton.classList.remove("bg-gray-400");
      actionButton.classList.add("bg-gray-700");
      actionButton.classList.add("hover:bg-gray-800");
    } else {
      actionButton.classList.add("bg-gray-400");
      actionButton.classList.remove("bg-gray-700", "hover:bg-gray-800");
    }
  });
});
