const input = "Alice";

function buildUser(value) {
    return {
        name: value
    };
}

const user = buildUser(input);

element.innerHTML = user.name;
