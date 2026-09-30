const input = request.query.name;

function buildUser(value) {
    return {
        name: value
    };
}

const user = buildUser(input);

element.innerHTML = user.name;
