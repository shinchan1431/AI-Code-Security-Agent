const userInput = request.query.name;

const content = getContent(userInput);

element.innerHTML = content;

function getContent(value) {
    return "Safe content";
}
