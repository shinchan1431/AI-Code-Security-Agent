const input = request.query.name;

const source = {
    name: input
};

const sourceAlias = source;

const target = {
    name: "safe text"
};

target.name = sourceAlias.name;

element.innerHTML = target.name;
