import passport from "passport";
import local from "passport-local";
import userModel from "../dao/models/user.model.js";
import { createHash, isValidPassword } from "../utils.js";

const LocalStrategy = local.Strategy;

const initializePassport = () => {
  passport.use(
    "register",
    new LocalStrategy(
      { passReqToCallback: true, usernameField: "email" },
      async (req, username, password, done) => {
        const { name, lastname, email } = req.body;
        //si faltan campos, se manda un mensaje de error
        if (!name || !lastname || !email || !password) {
          return done(null, false, {
            message: "Todos los campos son obligatorios",
          });
        }
        try {
          let user = await userModel.findOne({ email: username });
          if (user) {
            console.log("el usuario ya existe");
            return done(null, false, { message: "El usuario ya existe" });
          }
          const newUser = {
            name,
            lastname,
            email,
            role: "user",
            password: createHash(password),
          };
          let result = await userModel.create(newUser);
          return done(null, result);
        } catch (error) {
          return done(null, false, {
            message: "Error en el registro de usuario: " + error,
          });
        }
      }
    )
  );

  passport.use(
    "login",
    new LocalStrategy(
      { usernameField: "email" },
      async (username, password, done) => {
        try {
          let user;
          if (
            username === "adminCoder@coder.com" &&
            password === "adminCod3r123"
          ) {
            user = {
              name: "Coder",
              lastname: "House",
              email: "adminCoder@coder.com",
              role: "admin",
              admin: true,
            };
          } else {
            user = await userModel.findOne({ email: username });
            if (!user) {
              return done(null, false, { message: "El usuario no existe" });
            }
            if (!isValidPassword(user, password)) {
              return done(null, false, { message: "Contraseña incorrecta" });
            }
            user.role = "user";
            user.admin = false;
          }
          return done(null, user);
        } catch (error) {
          return done(null, false, { message: "Error en el login: " + error });
        }
      }
    )
  );

  passport.serializeUser(async (user, done) => {
    done(null, user._id);
  });

  passport.deserializeUser(async (id, done) => {
    try {
      let user = await userModel.findById(id);
      done(null, user);
    } catch (error) {
      req.session.messages = [];
      done("Error deserializando el usuario: " + error);
    }
  });
};

export default initializePassport;
