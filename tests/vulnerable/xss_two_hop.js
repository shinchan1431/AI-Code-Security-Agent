const userInput = request.query.name;
const html = "<div>" + userInput + "</div>";
const finalHtml = html;

element.innerHTML = finalHtml;
