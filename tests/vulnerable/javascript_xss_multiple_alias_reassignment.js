const input = request.query.name;

const source = {
    name: input
};

const alias = source;
const secondAlias = source;

alias = { name: "safe text" };

secondAlias.name = input;

element.innerHTML = source.name;
element.innerHTML = secondAlias.name;
element.innerHTML = alias.name;
