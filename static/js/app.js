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
 function navigate(newPage) {
   const alpineRoot = document.querySelector("[x-data]");
   alpineRoot.__x.$data.isLoading = true; // Show loading state
   alpineRoot.__x.$data.loadPage(newPage); // Load new content
 }

 async function loadPage(page) {
   try {
     // Update loading state
     this.isLoading = true;

     // Fetch the new content
     const response = await fetch(page);
     if (!response.ok) throw new Error(`Failed to load ${page}`);
     const html = await response.text();
     const parser = new DOMParser();
     const doc = parser.parseFromString(html, "text/html");
     const newContent = doc.querySelector('[x-html="content"]');

     // Replace content and update state
     if (newContent) this.content = newContent.innerHTML;

     // Update URL in the browser
     window.history.pushState({ page }, "", page);

     // Remove loading state
     this.isLoading = false;
     this.currentPage = page; // Update current page
   } catch (error) {
     console.error(error);
     this.content = `<p class="text-red-500">Error loading page content.</p>`;
     this.isLoading = false;
   }
 }

 // Handle browser back/forward navigation
 window.addEventListener("popstate", async (event) => {
   if (event.state && event.state.page) {
     const alpineRoot = document.querySelector("[x-data]");
     alpineRoot.__x.$data.isLoading = true; // Show loading state
     alpineRoot.__x.$data.loadPage(event.state.page); // Load new content
   }
 });