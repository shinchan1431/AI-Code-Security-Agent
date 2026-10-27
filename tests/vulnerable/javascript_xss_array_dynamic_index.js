const values = [window.location.search, "safe text"];
const index = getSelectedIndex();
const name = values[index];
document.body.innerHTML = name;
