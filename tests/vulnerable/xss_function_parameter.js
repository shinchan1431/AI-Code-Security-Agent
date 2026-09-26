const userInput = request.query.name;

render(userInput);

function render(value) {
    element.innerHTML = value;
}
