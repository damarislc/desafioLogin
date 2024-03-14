import express from "express";
import userModel from "../dao/models/user.model.js";
import passport from "passport";
import { createHash } from "../utils.js";

const router = express.Router();

/**
 * Ruta para guardar el usuario que se quiere registrar.
 * Se utiliza passport authenticate para la validación.
 * En mi caso cambié la forma de usarlo por medio de un callback
 * en vez del redirect para poder seguir mandando los mensajes de
 * error a mi front y manejar desde ahí como ve el error el usuario.
 */
router.post("/register", (req, res, next) => {
  passport.authenticate("register", (err, user, info) => {
    if (err) return next(err);
    if (!user) {
      return res.status(401).send({ status: "error", message: info.message });
    }
    res.status(200).send({
      status: "success",
      message: "Usuario creado correctamente",
    });
  })(req, res, next);
});

/**
 * Ruta para buscar al usario que quiere hacer login
 * al igual que en el register, se cambio el modo que se usa el auth.
 */
router.post("/login", (req, res, next) => {
  passport.authenticate("login", (err, user, info) => {
    if (err) return next(err);
    if (!user) {
      return res.status(401).send({
        status: "error",
        message: info.message,
      });
    }

    //crea un usuario en la sesion
    req.session.user = {
      name: user.name,
      lastname: user.lastname,
      email: user.email,
      role: user.role,
      admin: user.admin,
    };

    //manda un mensaje exitoso
    res.status(200).send({
      status: "success",
      payload: req.session.user,
      message: "login exitoso",
    });
  })(req, res, next);
});

router.get(
  "/github",
  passport.authenticate("github", { scope: ["user:email"] }),
  async (req, res) => {}
);

router.get(
  "/githubcallback",
  passport.authenticate("github", {
    failureRedirect: "/login",
    failureMessage: true,
  }),
  async (req, res) => {
    req.session.user = req.user;
    //manda un mensaje exitoso
    res.redirect("/products");
  }
);

//Ruta para restaurar la contraseña
router.post("/restore", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password)
      return res
        .status(400)
        .send({ status: "error", error: "Todos los campos son obligatorios" });
    const user = await userModel.findOne({ email });
    if (!user)
      return res
        .status(401)
        .send({ status: "error", error: "Usuario incorrecto" });
    user.password = createHash(password);
    await userModel.updateOne({ email }, { password: user.password });
    //manda un mensaje exitoso
    res.status(200).send({
      status: "success",
      message: "Contraseña actualizada correctamente",
    });
  } catch (error) {
    res.status(500).send(`Error al restablecer contraseña. ${error}`);
  }
});

//ruta para destruir la sesion cuando se hace logout
router.get("/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) return res.send({ status: "error", error: err });
    else res.send({ status: "success" });
  });
});

export default router;
