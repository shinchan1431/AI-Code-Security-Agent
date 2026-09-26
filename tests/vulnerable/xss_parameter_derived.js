const userInput = request.query.name;

render(userInput);

function render(value) {
    const content = value;
    element.innerHTML = content;
}
