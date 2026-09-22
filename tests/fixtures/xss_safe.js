const safeText = "Hello World";
const safeHtml = "<p>Static content</p>";

element.innerHTML = safeText;
element.outerHTML = safeHtml;
element.insertAdjacentHTML("beforeend", "<p>Static content</p>");
document.write("Hello World");
