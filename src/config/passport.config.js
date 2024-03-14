import passport from "passport";
import local from "passport-local";
import GitHubStrategy from "passport-github2";
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

  passport.use(
    "github",
    new GitHubStrategy(
      {
        clientID: "Iv1.83595609caccb0b1",
        clientSecret: "344948e31151eb6f48df4b6df0455c7570fd9a9f",
        callbackURL: "http://localhost:8080/api/sessions/githubcallback",
      },
      async (accessToken, refreshToken, profile, done) => {
        try {
          const user = await userModel.findOne({ email: profile._json.email });
          if (!user) {
            const newUser = {
              name: profile._json.name,
              lastname: "",
              email: profile._json.email,
              role: "user",
              password: "",
            };
            let createdUser = await userModel.create(newUser);
            done(null, createdUser);
          } else done(null, user);
        } catch (error) {
          return done(null, false, {
            message: "Error en el login con GitHub: " + error,
          });
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
