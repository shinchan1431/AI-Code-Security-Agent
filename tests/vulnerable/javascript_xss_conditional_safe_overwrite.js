const user = {};
user.name = req.query.name;

if (Math.random() > 0.5) {
    user.name = "safe text";
}

document.body.innerHTML = user.name;
