const admin = require("../../firebase");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

module.exports = async (req, res) => {
  if (req.method !== "POST")
    return res.status(405).json({ message: "Método no permitido" });

  const { email, password } = req.body;
  if (!email || !password)
    return res.status(400).json({ message: "Faltan datos" });

  try {
    const db = admin.firestore();
    const snap = await db.collection("users").where("email","==", email).get();
    if (snap.empty)
      return res.status(400).json({ message: "Usuario no encontrado" });

    const doc = snap.docs[0];
    const user = doc.data();

    const match = await bcrypt.compare(password, user.passwordHash);
    if (!match)
      return res.status(401).json({ message: "Credenciales inválidas" });

    const token = jwt.sign(
      { uid: doc.id, email },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );

    res.json({ uid: doc.id, token });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
};
