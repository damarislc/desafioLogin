import express from "express";
import userModel from "../dao/models/user.model.js";

const router = express.Router();

//Ruta para guardar el usuario que se quiere registrar
router.post("/register", async (req, res) => {
  //Recibe el contenido del form
  const { name, lastname, email, password } = req.body;

  try {
    //Busca si el email ya se ha registrado anteriormente
    const user = await userModel.findOne({ email });

    //si el usuario ya existe, se manda un mensaje de error
    if (user) {
      console.log("se encontro un usuario");
      return res
        .status(401)
        .send({ status: "error", message: "El email ya existe" });
    }

    //se asigna el rol de usuario por default
    let role = "user";

    //crea un nuevo usuario dentro de la base de datos
    await userModel.create({ name, lastname, email, password, role });

    //manda mensaje de que le usuario ha sido creado
    res.status(200).send({
      status: "success",
      message: "Usuario creado correctamente",
    });
  } catch (error) {
    //en caso de que haya habido un error, se manda el mensaje de error
    res.status(500).send({
      status: "error",
      message: `Error al crear el usuario. ${error}`,
    });
  }
});

//ruta para buscar al usario que quiere hacer login
router.post("/login", async (req, res) => {
  //recibe los datos del form
  const { email, password } = req.body;

  try {
    //valor booleano para poderlo usar mas facilmente en handlebars
    let isAdmin = false;
    let user;
    if (email === "adminCoder@coder.com" && password === "adminCod3r123") {
      isAdmin = true;
      user = {
        name: "Coder",
        lastname: "House",
        email: "adminCoder@coder.com",
        role: "admin",
        admin: isAdmin,
      };
    } else {
      //busa el usuario que coincida con el email y contraseña
      user = await userModel.findOne({ email, password });
    }
    //si el usuario no existe se manda mensaje de error
    if (!user) {
      return res.status(401).send({
        status: "error",
        message: "Usuario o contraseña incorrecto",
      });
    }

    //Valida si el role es admin para añadir un booleano para usarlo en handlebars

    //crea un usuario en la sesion
    req.session.user = {
      name: user.name,
      lastname: user.lastname,
      email: user.email,
      role: user.role,
      admin: isAdmin,
    };

    //manda un mensaje exitoso
    res.status(200).send({
      status: "success",
      payload: req.session.user,
      message: "login exitoso",
    });
  } catch (error) {
    //en caso de que haya habido un error, se manda el mensaje de error
    res.status(500).send({
      status: "error",
      message: `Error al obtener el usuario. ${error}`,
    });
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
