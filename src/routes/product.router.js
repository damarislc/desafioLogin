import express, { query } from "express";
import ProductManager from "../dao/productManager.js";

const router = express.Router();
//crea una instancia del ProductManager
const productManager = new ProductManager();

//Obtener todos los productos
router.get("/", (req, res) => {
  //se obtiene los parametros
  let limit = parseInt(req.query.limit);
  let page = parseInt(req.query.page);
  let sort = parseInt(req.query.sort);
  let status = req.query.status;
  let category = req.query.category;
  //se asigna un limite por default
  limit = limit ? limit : 10;
  //se asigna una pagina por default
  page = page ? page : 1;
  if (sort) sort = sort == -1 ? "desc" : "asc";

  //se guardan los parametros en un objeto
  const params = {
    limit,
    page,
    sort,
    status,
    category,
  };

  //Llama el método getProducts
  //si la promesa es exitosa manda el resultado
  //sino manda un mensaje de error
  productManager
    .getProducts(params)
    .then((products) => {
      //se manda el respond con las propiedades del paginate
      res.send({
        status: "success",
        payload: products.docs,
        totalPages: products.totalPages,
        prevPage: products.prevPage,
        nextPage: products.nextPage,
        page: products.page,
        hasPrevPage: products.hasPrevPage,
        hasNextPage: products.hasNextPage,
        prevLink: products.hasPrevPage
          ? `/products?page=${products.prevPage}`
          : null,
        nextLink: products.hasNextPage
          ? `/products?page=${products.nextPage}`
          : null,
      });
    })
    .catch((error) =>
      res.send({
        status: "error",
        error: "Error al obtener los productos, " + error,
      })
    );
});

//Obtener producto por id
router.get("/:pid", (req, res) => {
  //Obtiene el id del producto desde el params
  const pid = req.params.pid;
  //Llama el método getProductById para obtener el producto según su id
  //si la promesa es exitosa manda el resultado
  //sino manda un mensaje de error
  productManager
    .getProductById(pid)
    .then((product) => {
      if (product) {
        res.send({ status: "success", payload: product });
      } else {
        res.send({
          status: "error",
          error: `El producto con el id ${pid} no existe.`,
        });
      }
    })
    .catch((error) =>
      res.send({
        status: "error",
        error: "Error al obtener el producto, " + error,
      })
    );
});

//Añadir producto
router.post("/", (req, res) => {
  //Obtiene el json del product desde el body
  const product = req.body;
  //Llama el método addProduct para añadir el producto a la colección
  //si la promesa es exitosa manda el resultado
  //sino manda un mensaje de error
  productManager
    .addProduct(product)
    .then((result) => res.send({ status: "success", payload: result }))
    .catch((error) =>
      res.send({
        status: "error",
        error: "Error al añadir el producto, " + error,
      })
    );
});

//Actualizar producto
router.put("/:pid", (req, res) => {
  //Obtiene el id de prodcuto a actualizar y el json de los campos actualizados
  const pid = req.params.pid;
  const product = req.body;
  //Llama el método updateProduct con el id del producto y los nuevos campos
  //si la promesa es exitosa manda el resultado
  //sino manda un mensaje de error
  productManager
    .updateProduct(pid, product)
    .then((result) => {
      if (result) {
        res.send({
          status: "success",
          payload: { before: result[0], after: result[1] },
        });
      } else {
        res.send({
          status: "error",
          error: `El producto con el id ${pid} no existe.`,
        });
      }
    })
    .catch((error) =>
      res.send({
        status: "error",
        error: "Error al actualizar el producto, " + error,
      })
    );
});

//Eliminar producto
router.delete("/:pid", async (req, res) => {
  //Obtiene el id del producto desde el params
  const pid = req.params.pid;
  //Llama el método deleteProduct con el id del producto a eliminar
  //si la promesa es exitosa manda el resultado
  //sino manda un mensaje de error
  productManager
    .deleteProduct(pid)
    .then((result) => res.send({ status: "success", payload: result }))
    .catch((error) =>
      res.send({
        status: "error",
        error: "Error al eliminar el producto, " + error,
      })
    );
});

export default router;
