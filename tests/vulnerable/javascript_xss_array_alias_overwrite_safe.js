const items = [window.location.search, "safe"];
const alias = items;
items[0] = "safe text";
const rendered = alias[0];
element.innerHTML = rendered;
