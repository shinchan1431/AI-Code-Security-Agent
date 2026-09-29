const input = request.query.name;

function buildName(value) {
    return value.trim();
}

const result = buildName(input);

element.innerHTML = result;