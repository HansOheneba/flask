const termsCheckbox = document.getElementById("accept-terms");
const actionButton = document.getElementById("submitButton");

termsCheckbox.addEventListener("change", function () {

  actionButton.disabled = !termsCheckbox.checked;


  actionButton.classList.toggle("bg-gray-700", termsCheckbox.checked);
  actionButton.classList.toggle("hover:bg-gray-800", termsCheckbox.checked);
 if (termsCheckbox.checked) {
   actionButton.classList.remove("bg-gray-400");
 } else {

   actionButton.classList.add("bg-gray-400");
 }
});

