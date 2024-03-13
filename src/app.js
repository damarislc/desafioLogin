import express from "express";
import handlebars from "express-handlebars";
import { Server } from "socket.io";
import http from "http";
import __dirname from "./utils.js";
import cartRouter from "./routes/cart.router.js";
import productRouter from "./routes/product.router.js";
import sessionRouter from "./routes/session.router.js";
import viewsRouter from "./routes/views.router.js";
import path from "path";
import mongoose from "mongoose";
import MessageManager from "./dao/messageManager.js";
import { mongoURL } from "./config/config.js";
import MongoStore from "connect-mongo";
import session from "express-session";
import cookieParser from "cookie-parser";

const app = express();
const PORT = 8080;

//middlewares para el manejo del REST
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser("myParser"));

//Seteando session con mongo
app.use(
  session({
    store: MongoStore.create({ mongoUrl: mongoURL, ttl: 1000 }),
    secret: "m!Secr3t",
    resave: false,
    saveUninitialized: true,
  })
);

//Crea la conección con la base de datos
mongoose
  .connect(mongoURL)
  .then(() => console.log("Conectado a la BD"))
  .catch((error) => console.error("Error al conectarse a la BD", error));

//creando el http server
const httpServer = http.createServer(app);
httpServer.listen(PORT, () =>
  console.log(`Servidor corriendo en el puerto ${PORT}`)
);

//creando el servidor de sockets
const io = new Server(httpServer);

//Configuracion de handlebars
//se le dice al engine que la extendion de handbelars sera hbs
app.engine(".hbs", handlebars.engine({ extname: ".hbs" }));
//se le dice al engine que busque los archivos con la extension hbs
app.set("view engine", ".hbs");
//se le dice donde se encuentra el folder de las vistas
app.set("views", path.resolve(__dirname + "/views"));
//se le dice donde estan los archivos estaticos
app.use(express.static(__dirname + "/public"));
//asignacion de routers
app.use("/api/products", productRouter);
app.use("/api/carts", cartRouter);
app.use("/api/session", sessionRouter);
app.use("/", viewsRouter);

//crea una instancia del MessageManager
const messageManager = new MessageManager();
//crea un arreglo de usuarios
const users = {};

//Cuando se crea una conección con el socket
io.on("connection", (socket) => {
  console.log("Un usuario se ha conectado");
  //y se recibe el evento newUser
  socket.on("newUser", (userEmail) => {
    //almacena el email del usuario en el arreglo de usuarios con el indice del socket actual
    users[socket.id] = userEmail;
    //y emite el evento userConnected hacia el frontend
    io.emit("userConnected", userEmail);
  });

  //cuando se recibe el evento chatMessage
  socket.on("chatMessage", (message) => {
    //obtiene el email del arreglo con el id del socket correspondiente
    const userEmail = users[socket.id];

    //Almacena el mensaje y el email en la base de datos llamando al método addMessage
    //Si la promesa es exitosa, emite el evento message al frontEnd
    //sino, emite el evento error
    messageManager
      .addMessage(userEmail, message)
      .then(io.emit("message", { userEmail, message }))
      .catch((error) => io.emit("error", error));
  });

  //si se recibe el evento disconnect
  socket.on("disconnect", () => {
    //se elimina el usuario del arreglo
    const userEmail = users[socket.id];
    delete users[socket.id];
    io.emit("userDisconnected", userEmail);
  });
});
