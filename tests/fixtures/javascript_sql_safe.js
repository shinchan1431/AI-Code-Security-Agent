// Safe JavaScript SQL fixture

const userId = "123";

db.execute(
    "SELECT * FROM users WHERE id = ?",
    [userId]
);