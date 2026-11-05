const items = ["safe"];
const alias = items;
items[0] = window.location.search;
const rendered = alias[0];
element.innerHTML = rendered;
