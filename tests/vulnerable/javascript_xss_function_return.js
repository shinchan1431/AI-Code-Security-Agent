const input = request.query.name;

function getName(value) {
    return value;
}

const result = getName(input);

element.innerHTML = result;