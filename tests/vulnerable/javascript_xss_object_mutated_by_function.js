const profile = {};

function setName(target, value) {
    target.name = value;
}

setName(profile, req.query.name);

const element = document.getElementById("output");
element.innerHTML = profile.name;
