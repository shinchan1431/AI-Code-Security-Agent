const userInput = request.query.name;
const emailInput = request.query.email;
const user = {
    name: userInput,
    email: emailInput
};
const { name, email } = user;
element.innerHTML = name;
element.innerHTML = email;
