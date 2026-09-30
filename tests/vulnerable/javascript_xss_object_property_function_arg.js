const input = request.query.name;

const user = {
    name: input
};

function render(value) {
    element.innerHTML = value;
}

render(user.name);