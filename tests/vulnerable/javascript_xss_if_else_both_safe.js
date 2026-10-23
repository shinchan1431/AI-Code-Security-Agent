const user = {};
user.name = req.query.name;

if (Math.random() > 0.5) {
    user.name = "safe one";
} else {
    user.name = "safe two";
}

document.body.innerHTML = user.name;
