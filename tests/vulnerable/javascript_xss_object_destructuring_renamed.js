const userInput = request.query.name;
const user = {
    name: userInput
};
const { name: displayName } = user;
element.innerHTML = displayName;
