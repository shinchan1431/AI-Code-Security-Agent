const userInput = request.query.name;

const data = {
    name: userInput
};

element.innerHTML = data.name;
