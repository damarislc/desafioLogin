import mongoose from "mongoose";

const cartsCollection = "carts";

/**
 * Schema de la coleccion carts, el cual se compone de un arreglo de productos
 * que contiene un objeto con el id que coresponde a la coleccion de products
 * y un quantity
 */
const cartSchema = new mongoose.Schema({
  products: {
    type: [
      {
        productId: {
          type: mongoose.Schema.Types.ObjectId,
          ref: "products",
          required: true,
        },
        quantity: { type: Number, integer: true, required: true },
      },
    ],
    default: [],
  },
});

const cartModel = mongoose.model(cartsCollection, cartSchema);

export default cartModel;
