const user = {};
user.name = req.query.name;

if (Math.random() > 0.5) {
    user.name = "conditional safe";
}

user.name = "unconditionally safe";
document.body.innerHTML = user.name;
