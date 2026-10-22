function updateProfile(profile, value) {
    profile.name = value;
}

const unsafe = { name: "safe" };
updateProfile(unsafe, request.query.name);
document.body.innerHTML = unsafe.name;

const safe = { name: "safe" };
updateProfile(safe, "Alice");
document.body.innerHTML = safe.name;
