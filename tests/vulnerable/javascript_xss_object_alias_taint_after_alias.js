const user = {};
const alias = user;

user.name = req.query.name;
document.body.innerHTML = alias.name;
