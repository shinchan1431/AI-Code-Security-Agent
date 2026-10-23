function setName(target, value) {
    target.name = value;
}

function copyName(source, target) {
    target.name = source.name;
}

const source = {};
const target = {};

setName(source, req.query.name);
copyName(source, target);
document.body.innerHTML = target.name;
