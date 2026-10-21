const profile = {};

function setName(target, value) {
    target.name = value;
}

setName(profile, req.query.name);
setName(profile, "Alice");

const element = document.getElementById("output");
element.innerHTML = profile.name;