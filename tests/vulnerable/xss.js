const userInput = request.query.name;

element.innerHTML = userInput;

element.outerHTML = userInput;

element.insertAdjacentHTML("beforeend", userInput);

document.write(userInput);