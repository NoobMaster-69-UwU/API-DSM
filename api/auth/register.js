const admin = require("../../firebase");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

module.exports = async (req, res) => {
  if (req.method !== "POST")
    return res.status(405).json({ message: "Método no permitido" });

  const { username, email, password } = req.body;

  if (!username || !email || !password)
    return res.status(400).json({ message: "Faltan datos" });

  try {
    const db = admin.firestore();

    const exists = await db.collection("users").where("email","==", email).get();
    if (!exists.empty)
      return res.status(400).json({ message: "Email ya registrado" });

    const passwordHash = await bcrypt.hash(password, 10);
    const newUser = {
      username,
      email,
      passwordHash,
      createdAt: new Date().toISOString()
    };

    const ref = await db.collection("users").add(newUser);

    const token = jwt.sign(
      { uid: ref.id, email },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );

    res.json({ uid: ref.id, token });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
};
