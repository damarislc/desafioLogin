import express from "express";

const router = express.Router();

//Por defecto mandar a products
router.get("/", (req, res) => {
  res.redirect("/products");
});

//Renderea la página del chat
router.get("/chat", (req, res) => {
  res.render("chat", { title: "Chat" });
});

//Renderea la pagina de login
router.get("/login", (req, res) => {
  res.render("login", { title: "Login" });
});

//Renderea la pagina de registro
router.get("/register", (req, res) => {
  res.render("register", { title: "Registro" });
});

//Obtiene los productos desde un fetch de la api de products
router.get("/products", (req, res) => {
  if (!req.session?.user) {
    return res.redirect("/login");
  }
  const user = req.session.user;
  /** Se obtiene los parametros del request
   * por el momento el frontEnd solo utiliza limit y page.
   */
  let limit = parseInt(req.query.limit);
  let page = parseInt(req.query.page);
  let sort = req.query.sort;
  let status = req.query.status;
  let category = req.query.category;
  limit = limit ? limit : 10;
  page = page ? page : 1;
  if (sort) sort = parseInt(sort) == -1 ? "desc" : "asc";

  //Se guardan en un objeto params
  const params = {
    limit,
    page,
  };

  if (status) params.status = status;
  if (category) params.category = category;
  if (sort) params.sort = sort;

  //y se crea un url params para añadirse a la url
  const urlParams = new URLSearchParams(params);

  //se concatena la url con el url params
  const url = `http://localhost:8080/api/products?${urlParams.toString()}`;

  //se llama al fetch con la url completa
  fetch(url)
    .then((res) => res.json())
    .then((data) => {
      //si la data contiene el estatus success
      if (data.status === "success") {
        //se renderea la vista de productos
        res.render("products", {
          data,
          title: "Listado de productos",
          user,
        });
      } else {
        //sino, se manda que hubo un error en el servidor
        res.status(500).send("Error al obtener los productos");
      }
    })
    .catch((err) =>
      res.status(500).send(`Error en el fetch de productos. ${err}`)
    );
});

//obtiene el carrito desde un fetch de la api de carts
router.get("/carts/:cid", (req, res) => {
  //Se obtiene el id del carrito
  const cid = req.params.cid;
  //y se hace un fetch del carrito
  fetch(`http://localhost:8080/api/carts/${cid}`)
    .then((res) => res.json())
    .then((data) => {
      //si la data contiene el estatus success
      if (data.status === "success") {
        const products = data.payload.products;
        //se renderea la vista del carrito
        res.render("carts", { products, title: "Carrito" });
      } else {
        //sino, se manda que hubo un error en el servidor
        res.status(500).send("Error al obtener el carrito");
      }
    })
    .catch((err) =>
      res.status(500).send(`Error en el fetch de carrito. ${err}`)
    );
});

export default router;
