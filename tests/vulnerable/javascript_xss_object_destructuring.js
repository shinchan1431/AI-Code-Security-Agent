const userInput = request.query.name;
const user = {
    name: userInput
};
const { name } = user;
element.innerHTML = name;
